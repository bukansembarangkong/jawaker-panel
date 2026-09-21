package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apps"
	"github.com/bukansembarangkong/jawaker-panel/internal/jobs"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodes"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/projects"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AppWorkerOptions configures the worker executing application deployments.
type AppWorkerOptions struct {
	Pool         *pgxpool.Pool
	Apps         *apps.Store
	Projects     *projects.Store
	Secrets      *secret.Store
	Dispatcher   *nodes.Dispatcher
	Logger       *slog.Logger
	Owner        string
	LeaseTTL     time.Duration
	PollInterval time.Duration
}

// NewAppDeployWorker constructs a jobs.Worker configured for "app.deploy" jobs.
func NewAppDeployWorker(opts AppWorkerOptions) (*jobs.Worker, error) {
	if opts.Pool == nil {
		return nil, errors.New("controller: database pool is required for app worker")
	}
	if opts.Apps == nil {
		return nil, errors.New("controller: apps store is required for app worker")
	}
	if opts.Owner == "" {
		opts.Owner = fmt.Sprintf("controller-app-worker-%d", time.Now().UnixNano())
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	handler := NewAppDeployHandler(opts.Pool, opts.Apps, opts.Projects, opts.Secrets, opts.Dispatcher, logger)

	return jobs.NewWorker(jobs.WorkerConfig{
		Pool:         opts.Pool,
		Logger:       logger,
		Owner:        opts.Owner,
		LeaseTTL:     opts.LeaseTTL,
		PollInterval: opts.PollInterval,
		Types:        []string{JobTypeAppDeploy},
		Handlers: map[string]jobs.Handler{
			JobTypeAppDeploy: handler,
		},
	})
}

// NewAppDeployHandler returns the jobs.Handler executing the app deployment pipeline.
func NewAppDeployHandler(
	pool *pgxpool.Pool,
	store *apps.Store,
	projStore *projects.Store,
	secrets *secret.Store,
	dispatcher *nodes.Dispatcher,
	logger *slog.Logger,
) jobs.Handler {
	return func(ctx context.Context, lease *jobs.Lease) error {
		job := lease.Job()
		appID, _ := job.Payload["app_id"].(string)
		depID, _ := job.Payload["deployment_id"].(string)
		reqID := job.RequestID

		if appID == "" || depID == "" {
			_ = lease.Fail(ctx, "invalid_payload", "job payload missing required fields (app_id or deployment_id)")
			return nil
		}

		if err := lease.MarkRunning(ctx); err != nil {
			logger.Error("app deploy worker: mark running failed", "job_id", job.ID, "error", err)
			return err
		}

		// Advance deployment record to running.
		_, _ = store.UpdateDeploymentState(ctx, depID, apps.UpdateDeploymentStateParams{
			State: apps.DeployRunning,
		})

		if dispatcher == nil {
			failSummary := "node dispatcher not available on this controller instance"
			_, _ = store.UpdateDeploymentState(ctx, depID, apps.UpdateDeploymentStateParams{
				State:        apps.DeployFailed,
				ErrorCode:    "dispatcher_unavailable",
				ErrorSummary: failSummary,
			})
			_ = lease.FailStep(ctx, 0, "dispatcher_unavailable", failSummary)
			_ = lease.Fail(ctx, "dispatcher_unavailable", failSummary)
			return nil
		}

		// Load application details.
		app, err := store.GetApp(ctx, appID)
		if err != nil {
			failSummary := fmt.Sprintf("failed to load app record: %v", err)
			_, _ = store.UpdateDeploymentState(ctx, depID, apps.UpdateDeploymentStateParams{
				State:        apps.DeployFailed,
				ErrorCode:    "app_lookup_failed",
				ErrorSummary: failSummary,
			})
			_ = lease.FailStep(ctx, 0, "app_lookup_failed", failSummary)
			_ = lease.Fail(ctx, "app_lookup_failed", failSummary)
			return nil
		}

		// Load parent project to obtain project slug.
		var projectSlug string
		if projStore != nil {
			if proj, pErr := projStore.Get(ctx, app.ProjectID); pErr == nil {
				projectSlug = proj.Slug
			}
		}
		if projectSlug == "" {
			// Fallback query if projStore is nil or not loaded.
			_ = pool.QueryRow(ctx, `SELECT slug FROM projects WHERE id = $1`, app.ProjectID).Scan(&projectSlug)
		}
		if projectSlug == "" {
			failSummary := "failed to resolve parent project slug"
			_, _ = store.UpdateDeploymentState(ctx, depID, apps.UpdateDeploymentStateParams{
				State:        apps.DeployFailed,
				ErrorCode:    "project_lookup_failed",
				ErrorSummary: failSummary,
			})
			_ = lease.Fail(ctx, "project_lookup_failed", failSummary)
			return nil
		}

		// Load deployment record.
		dep, err := store.GetDeployment(ctx, depID)
		if err != nil {
			failSummary := fmt.Sprintf("failed to load deployment record: %v", err)
			_ = lease.Fail(ctx, "deployment_lookup_failed", failSummary)
			return nil
		}

		// --------------------------------------------------------------------
		// Step 0: fetch (Resolve credentials and prepare git spec)
		// --------------------------------------------------------------------
		if stepErr := lease.StartStep(ctx, 0, "fetch"); stepErr != nil {
			logger.Error("app deploy worker: start fetch step failed", "job_id", job.ID, "error", stepErr)
			return stepErr
		}

		var sshKeyPEM string
		credKind := "none"
		if app.GitCredentialRef != nil && *app.GitCredentialRef != "" {
			if secrets != nil {
				val, sErr := secrets.Open(ctx, *app.GitCredentialRef)
				if sErr != nil {
					failSummary := fmt.Sprintf("failed to resolve git credential: %v", sErr)
					_, _ = store.UpdateDeploymentState(ctx, depID, apps.UpdateDeploymentStateParams{
						State:        apps.DeployFailed,
						ErrorCode:    "secret_resolution_failed",
						ErrorSummary: failSummary,
					})
					_ = lease.FailStep(ctx, 0, "secret_resolution_failed", failSummary)
					_ = lease.Fail(ctx, "secret_resolution_failed", failSummary)
					return nil
				}
				sshKeyPEM = val
				credKind = "ssh_key"
			}
		}

		// The handler validates commit_sha before enqueueing, so its absence
		// here is a payload integrity failure, not a user error.
		commitSHA := ""
		if dep.CommitSHA != nil {
			commitSHA = *dep.CommitSHA
		}
		if commitSHA == "" {
			failSummary := "deployment record has no commit_sha; the node fetches by exact SHA"
			_, _ = store.UpdateDeploymentState(ctx, depID, apps.UpdateDeploymentStateParams{
				State:        apps.DeployFailed,
				ErrorCode:    "missing_commit_sha",
				ErrorSummary: failSummary,
			})
			_ = lease.FailStep(ctx, 0, "missing_commit_sha", failSummary)
			_ = lease.Fail(ctx, "missing_commit_sha", failSummary)
			return nil
		}

		_ = lease.CompleteStep(ctx, 0, map[string]any{
			"repo_url":        app.GitRepoURL,
			"git_ref":         dep.GitRef,
			"credential_kind": credKind,
		})

		// --------------------------------------------------------------------
		// Step 1: build (Resolve environment variables and secret refs)
		// --------------------------------------------------------------------
		if stepErr := lease.StartStep(ctx, 1, "build"); stepErr != nil {
			logger.Error("app deploy worker: start build step failed", "job_id", job.ID, "error", stepErr)
			return stepErr
		}

		rawEnvList, err := store.ListEnvVars(ctx, app.ID)
		if err != nil {
			failSummary := fmt.Sprintf("failed to list env vars: %v", err)
			_, _ = store.UpdateDeploymentState(ctx, depID, apps.UpdateDeploymentStateParams{
				State:        apps.DeployFailed,
				ErrorCode:    "env_vars_lookup_failed",
				ErrorSummary: failSummary,
			})
			_ = lease.FailStep(ctx, 1, "env_vars_lookup_failed", failSummary)
			_ = lease.Fail(ctx, "env_vars_lookup_failed", failSummary)
			return nil
		}

		wireEnv := make([]nodewire.EnvEntryWire, 0, len(rawEnvList))
		for _, ev := range rawEnvList {
			var val string
			if ev.ValueSource == apps.ValueLiteral && ev.LiteralValue != nil {
				val = *ev.LiteralValue
			} else if ev.ValueSource == apps.ValueSecretRef && ev.SecretRef != nil {
				if secrets == nil {
					failSummary := fmt.Sprintf("secret store unavailable to resolve secret ref for %q", ev.Name)
					_, _ = store.UpdateDeploymentState(ctx, depID, apps.UpdateDeploymentStateParams{
						State:        apps.DeployFailed,
						ErrorCode:    "secret_store_unavailable",
						ErrorSummary: failSummary,
					})
					_ = lease.FailStep(ctx, 1, "secret_store_unavailable", failSummary)
					_ = lease.Fail(ctx, "secret_store_unavailable", failSummary)
					return nil
				}
				sVal, sErr := secrets.Open(ctx, *ev.SecretRef)
				if sErr != nil {
					failSummary := fmt.Sprintf("failed to resolve secret ref for %q: %v", ev.Name, sErr)
					_, _ = store.UpdateDeploymentState(ctx, depID, apps.UpdateDeploymentStateParams{
						State:        apps.DeployFailed,
						ErrorCode:    "secret_resolution_failed",
						ErrorSummary: failSummary,
					})
					_ = lease.FailStep(ctx, 1, "secret_resolution_failed", failSummary)
					_ = lease.Fail(ctx, "secret_resolution_failed", failSummary)
					return nil
				}
				val = sVal
			}
			wireEnv = append(wireEnv, nodewire.EnvEntryWire{
				Name:  ev.Name,
				Value: val,
			})
		}

		// Construct typed deploy input.
		deployInput := nodewire.AppDeployInput{
			App: nodewire.AppSpec{
				ProjectSlug: projectSlug,
				AppSlug:     app.Slug,
				RuntimeType: app.RuntimeType,
				Port:        app.Port,
			},
			Git: nodewire.GitSpec{
				RepoURL:        app.GitRepoURL,
				CommitSHA:      commitSHA,
				CredentialKind: credKind,
				SSHKeyPEM:      sshKeyPEM,
			},
			Build: nodewire.CommandSpecWire{
				Program: app.BuildProgram,
				Args:    app.BuildArgs,
			},
			Start: nodewire.CommandSpecWire{
				Program: app.StartProgram,
				Args:    app.StartArgs,
			},
			Env:        wireEnv,
			WorkingDir: app.WorkingDir,
		}
		if app.HealthPath != nil {
			deployInput.App.HealthPath = *app.HealthPath
		}

		_ = lease.CompleteStep(ctx, 1, map[string]any{
			"env_count": len(wireEnv),
		})

		// --------------------------------------------------------------------
		// Step 2: activate (Dispatch atomic deployment to host node)
		// --------------------------------------------------------------------
		if err := lease.StartStep(ctx, 2, "activate"); err != nil {
			logger.Error("app deploy worker: start activate step failed", "job_id", job.ID, "error", err)
			return err
		}

		result, deployErr := dispatcher.DeployApp(ctx, app.ServerID, reqID, deployInput)
		if deployErr != nil || !result.Deployed {
			state := apps.DeployFailed
			failSummary := "deployment failed on host"
			if deployErr != nil {
				failSummary = fmt.Sprintf("deploy node operation failed: %v", deployErr)
			} else if result.RolledBack {
				state = apps.DeployRolledBack
				failSummary = fmt.Sprintf("health check failed; release rolled back: %s", result.RollbackReason)
			} else if result.BuildOutput != "" {
				failSummary = result.BuildOutput
			}

			_, _ = store.UpdateDeploymentState(ctx, depID, apps.UpdateDeploymentStateParams{
				State:        state,
				ErrorCode:    "node_deploy_failed",
				ErrorSummary: failSummary,
			})
			_ = lease.FailStep(ctx, 2, "node_deploy_failed", failSummary)
			_ = lease.Fail(ctx, "node_deploy_failed", failSummary)
			return nil
		}

		_ = lease.CompleteStep(ctx, 2, map[string]any{
			"release_path": result.ReleasePath,
			"current_path": result.CurrentPath,
			"commit_sha":   result.CommitSHA,
		})

		// --------------------------------------------------------------------
		// Step 3: health (Record release, set current, advance state)
		// --------------------------------------------------------------------
		if err := lease.StartStep(ctx, 3, "health"); err != nil {
			logger.Error("app deploy worker: start health step failed", "job_id", job.ID, "error", err)
			return err
		}

		resolvedCommit := result.CommitSHA
		if strings.TrimSpace(resolvedCommit) == "" {
			resolvedCommit = commitSHA
		}

		release, relErr := store.CreateRelease(ctx, app.ID, dep.ID, result.ReleasePath, resolvedCommit)
		if relErr != nil {
			logger.Error("app deploy worker: create release failed", "app_id", app.ID, "error", relErr)
			_, _ = store.UpdateDeploymentState(ctx, depID, apps.UpdateDeploymentStateParams{
				State:        apps.DeployFailed,
				ErrorCode:    "release_record_failed",
				ErrorSummary: relErr.Error(),
			})
			_ = lease.FailStep(ctx, 3, "release_record_failed", relErr.Error())
			_ = lease.Fail(ctx, "release_record_failed", relErr.Error())
			return nil
		}

		if _, markErr := store.MarkCurrentRelease(ctx, release.ID, app.ID); markErr != nil {
			logger.Error("app deploy worker: mark current release failed", "release_id", release.ID, "error", markErr)
		}

		// Deployment succeeded!
		_, _ = store.UpdateDeploymentState(ctx, depID, apps.UpdateDeploymentStateParams{
			State: apps.DeploySucceeded,
		})

		_ = lease.CompleteStep(ctx, 3, map[string]any{
			"health_state": result.HealthState,
			"release_id":   release.ID,
		})

		if err := lease.Complete(ctx); err != nil {
			logger.Error("app deploy worker: complete job failed", "job_id", job.ID, "error", err)
			return err
		}

		return nil
	}
}
