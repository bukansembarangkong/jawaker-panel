package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/jobs"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodes"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/revisions"
	"github.com/bukansembarangkong/jawaker-panel/internal/sites"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SiteWorkerOptions configures the worker executing site background operations.
type SiteWorkerOptions struct {
	Pool         *pgxpool.Pool
	Sites        *sites.Store
	Dispatcher   *nodes.Dispatcher
	Logger       *slog.Logger
	Owner        string
	LeaseTTL     time.Duration
	PollInterval time.Duration
}

// NewSiteApplyWorker constructs a jobs.Worker configured specifically for the
// "site.apply" job type.
//
// The worker binds the job lifecycle to the revisions lifecycle and the node
// dispatcher, executing configuration candidates asynchronously per
// ARCHITECTURE.md §15 and API.md §7.
func NewSiteApplyWorker(opts SiteWorkerOptions) (*jobs.Worker, error) {
	if opts.Pool == nil {
		return nil, errors.New("controller: database pool is required for site worker")
	}
	if opts.Sites == nil {
		return nil, errors.New("controller: sites store is required for site worker")
	}
	if opts.Owner == "" {
		opts.Owner = fmt.Sprintf("controller-site-worker-%d", time.Now().UnixNano())
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	handler := NewSiteApplyHandler(opts.Pool, opts.Sites, opts.Dispatcher, logger)

	return jobs.NewWorker(jobs.WorkerConfig{
		Pool:         opts.Pool,
		Logger:       logger,
		Owner:        opts.Owner,
		LeaseTTL:     opts.LeaseTTL,
		PollInterval: opts.PollInterval,
		Types:        []string{JobTypeSiteApply},
		Handlers: map[string]jobs.Handler{
			JobTypeSiteApply: handler,
		},
	})
}

// siteWorkerActorID is the system actor identity used by the job worker when
// updating the revisions lifecycle. A job's requestID provides correlation;
// the actorID is the job engine's own identity for audit attribution.
const siteWorkerActorID = "site-apply-worker"

// NewSiteApplyHandler returns the jobs.Handler executing the two-step
// (validate -> apply) pipeline for a candidate configuration.
func NewSiteApplyHandler(pool *pgxpool.Pool, store *sites.Store, dispatcher *nodes.Dispatcher, logger *slog.Logger) jobs.Handler {
	return func(ctx context.Context, lease *jobs.Lease) error {
		job := lease.Job()
		siteID, _ := job.Payload["site_id"].(string)
		revID, _ := job.Payload["revision_id"].(string)
		config, _ := job.Payload["config"].(string)
		filename, _ := job.Payload["filename"].(string)
		reqID := job.RequestID

		if siteID == "" || revID == "" || config == "" || filename == "" {
			_ = lease.Fail(ctx, "invalid_payload", "job payload missing required fields (site_id, revision_id, config, or filename)")
			return nil
		}

		// Mark the leased job as running.
		if err := lease.MarkRunning(ctx); err != nil {
			logger.Error("site apply worker: mark running failed", "job_id", job.ID, "error", err)
			return err
		}

		if dispatcher == nil {
			failSummary := "dispatcher not available on this controller instance"
			_ = recordApplyFailure(ctx, pool, revID, "dispatcher_unavailable", failSummary, siteWorkerActorID, reqID, job.ID)
			_ = lease.FailStep(ctx, 0, "dispatcher_unavailable", failSummary)
			_ = lease.Fail(ctx, "dispatcher_unavailable", failSummary)
			return nil
		}

		// --------------------------------------------------------------------
		// Step 0: Pre-flight validate candidate on node.
		// --------------------------------------------------------------------
		if err := lease.StartStep(ctx, 0, "validate"); err != nil {
			logger.Error("site apply worker: start validate step failed", "job_id", job.ID, "error", err)
			return err
		}

		valResult, valErr := dispatcher.ValidateWebConfig(ctx, job.ServerID, reqID, siteID, nodewire.WebConfigValidateInput{
			Config:   config,
			Filename: filename,
		})

		if valErr != nil || !valResult.Valid {
			failSummary := "candidate configuration failed pre-apply validation"
			if valErr != nil {
				failSummary = fmt.Sprintf("node validation call failed: %v", valErr)
			} else if valResult.Output != "" {
				failSummary = valResult.Output
			}

			// Record the failed validation on the revision. It stays in DRAFT
			// with the findings attached — an invalid candidate never reaches
			// validated state, so there is no apply to fail. Calling
			// revisions.Apply here would be refused (it requires validated
			// state) and would misreport the lifecycle.
			_, _ = revisions.MarkValidated(ctx, pool, revID, revisions.ValidationResult{
				OK:      false,
				Summary: failSummary,
			}, siteWorkerActorID, reqID)

			_ = lease.FailStep(ctx, 0, "validation_failed", failSummary)
			_ = lease.Fail(ctx, "validation_failed", failSummary)
			return nil
		}

		// Validation passed: mark revision validated.
		if _, err := revisions.MarkValidated(ctx, pool, revID, revisions.ValidationResult{
			OK:      true,
			Summary: "candidate configuration passed node validation",
		}, siteWorkerActorID, reqID); err != nil {
			logger.Error("site apply worker: mark revision validated failed", "revision_id", revID, "error", err)
			_ = lease.FailStep(ctx, 0, "lifecycle_error", err.Error())
			_ = lease.Fail(ctx, "lifecycle_error", err.Error())
			return nil
		}

		if err := lease.CompleteStep(ctx, 0, map[string]any{
			"tool":   valResult.Tool,
			"output": valResult.Output,
		}); err != nil {
			return err
		}

		// --------------------------------------------------------------------
		// Step 1: Apply live configuration to host node.
		// --------------------------------------------------------------------
		if err := lease.StartStep(ctx, 1, "apply"); err != nil {
			logger.Error("site apply worker: start apply step failed", "job_id", job.ID, "error", err)
			return err
		}

		applyResult, applyErr := dispatcher.ApplyWebConfig(ctx, job.ServerID, reqID, nodewire.WebConfigApplyInput{
			Config:   config,
			Filename: filename,
		})

		if applyErr != nil || !applyResult.Applied {
			failSummary := "failed to apply configuration to host"
			if applyErr != nil {
				failSummary = fmt.Sprintf("apply node operation failed: %v", applyErr)
			} else if applyResult.RolledBack {
				failSummary = fmt.Sprintf("candidate rejected by nginx full test; previous configuration restored: %s", applyResult.Output)
			} else if applyResult.Output != "" {
				failSummary = applyResult.Output
			}

			_ = recordApplyFailure(ctx, pool, revID, "apply_failed", failSummary, siteWorkerActorID, reqID, job.ID)
			_ = lease.FailStep(ctx, 1, "apply_failed", failSummary)
			_ = lease.Fail(ctx, "apply_failed", failSummary)
			return nil
		}

		// Apply succeeded on host: update revision lifecycle and site applied_revision_id.
		if _, err := revisions.Apply(ctx, pool, revID, revisions.ApplyResult{
			JobID:  job.ID,
			Failed: false,
		}, siteWorkerActorID, reqID); err != nil {
			logger.Error("site apply worker: mark revision applied failed", "revision_id", revID, "error", err)
			_ = lease.FailStep(ctx, 1, "apply_recording_failed", err.Error())
			_ = lease.Fail(ctx, "apply_recording_failed", err.Error())
			return nil
		}

		if _, err := store.SetAppliedRevision(ctx, siteID, revID); err != nil {
			// Non-fatal: revision state is already applied in DB; site record
			// will be corrected on next health check or revision query.
			logger.Error("site apply worker: set site applied revision failed",
				"site_id", siteID, "revision_id", revID, "error", err)
		}

		if err := lease.CompleteStep(ctx, 1, map[string]any{
			"applied":   true,
			"live_path": applyResult.LivePath,
			"tool":      applyResult.Tool,
		}); err != nil {
			return err
		}

		if err := lease.Complete(ctx); err != nil {
			logger.Error("site apply worker: complete job failed", "job_id", job.ID, "error", err)
			return err
		}

		return nil
	}
}

func recordApplyFailure(ctx context.Context, pool *pgxpool.Pool, revID, code, summary, actorID, reqID, jobID string) error {
	_, err := revisions.Apply(ctx, pool, revID, revisions.ApplyResult{
		JobID:        jobID,
		Failed:       true,
		ErrorCode:    code,
		ErrorSummary: summary,
	}, actorID, reqID)
	return err
}
