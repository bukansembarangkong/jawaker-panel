import { useCallback, useEffect, useRef, useState } from 'react';
import { goeyToast } from 'goey-toast';

import {
  api,
  isStepUpRequired,
  primeCsrf,
  type App,
  type DeployAccepted,
  type Deployment,
  type EnvVar,
  type JobStatus,
  type Project,
  type Release,
  type WebhookToken,
} from '../api/client';
import { StepUpPrompt } from '../components/StepUpPrompt';
import {
  EmptyState,
  ErrorNote,
  Field,
  StatusBadge,
  Modal,
  ConfirmModal,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
  type OperationalState,
} from '../components/ui';

/** Terminal job states — poll stops. */
const JOB_TERMINAL = new Set(['succeeded', 'failed', 'dead_letter', 'canceled']);

function mapAppState(app: App): OperationalState {
  if (app.state === 'active') return 'Healthy';
  if (app.state === 'suspended') return 'Warning';
  if (app.state === 'pending_delete') return 'Warning';
  return 'Disabled';
}

function mapDeployState(state: string): OperationalState {
  if (state === 'succeeded') return 'Healthy';
  if (state === 'running') return 'Pending';
  if (state === 'queued') return 'Pending';
  if (state === 'failed' || state === 'rolled_back') return 'Critical';
  return 'Disabled';
}

function formatTs(value: string | null | undefined): string {
  if (!value) return '-';
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function toError(e: unknown): Error {
  return e instanceof Error ? e : new Error(String(e));
}

export function AppsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [apps, setApps] = useState<App[]>([]);
  const [selectedApp, setSelectedApp] = useState<App | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [stepUpPending, setStepUpPending] = useState(false);
  const [stepUpAction, setStepUpAction] = useState<(() => Promise<void>) | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);

  const selectApp = (a: App | null) => {
    setSelectedApp(a);
    window.location.hash = a ? `#/apps/${a.id}` : '#/apps';
  };

  const loadProjects = useCallback(async () => {
    try {
      const data = await api.listProjects({ state: 'active', limit: 50 });
      const projs = data.projects || [];
      setProjects(projs);
      setSelectedProject((prev) => prev ?? projs[0] ?? null);
    } catch (e: unknown) {
      setError(toError(e));
    }
  }, []);

  const loadApps = useCallback(async (projectId: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listApps(projectId, { limit: 50 });
      const loaded = data.apps || [];
      setApps(loaded);

      const appIdFromHash = window.location.hash.startsWith('#/apps/')
        ? window.location.hash.slice('#/apps/'.length)
        : null;
      if (appIdFromHash) {
        const match = loaded.find((a) => a.id === appIdFromHash);
        if (match) setSelectedApp(match);
      }
    } catch (e: unknown) {
      setError(toError(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadProjects();
  }, [loadProjects]);

  useEffect(() => {
    if (selectedProject) void loadApps(selectedProject.id);
  }, [selectedProject, loadApps]);

  useEffect(() => {
    const handleHash = () => {
      const h = window.location.hash;
      if (h === '#/apps' || h === '#/apps/') {
        setSelectedApp(null);
      } else if (h.startsWith('#/apps/')) {
        const id = h.slice('#/apps/'.length);
        const match = apps.find((a) => a.id === id);
        if (match) setSelectedApp(match);
      }
    };
    window.addEventListener('hashchange', handleHash);
    return () => window.removeEventListener('hashchange', handleHash);
  }, [apps]);

  const onElevationRequired = (action: () => Promise<void>) => {
    setStepUpAction(() => action);
    setStepUpPending(true);
  };

  if (stepUpPending && stepUpAction) {
    return (
      <StepUpPrompt
        onElevated={async () => {
          setStepUpPending(false);
          await stepUpAction();
          setStepUpAction(null);
        }}
        onCancel={() => {
          setStepUpPending(false);
          setStepUpAction(null);
        }}
      />
    );
  }

  if (selectedApp && selectedProject) {
    return (
      <AppDetail
        app={selectedApp}
        project={selectedProject}
        onBack={() => selectApp(null)}
        onDeleted={() => {
          selectApp(null);
          void loadApps(selectedProject.id);
        }}
        onElevationRequired={onElevationRequired}
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Apps</h1>
          <p className="text-sm text-slate-500">Deploy and manage application builds across projects.</p>
        </div>
        {selectedProject && (
          <button
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
            onClick={() => setShowCreateForm(true)}
          >
            + New App
          </button>
        )}
      </div>

      {error && <ErrorNote error={error} />}

      {/* Project picker */}
      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <label className="block text-sm font-medium text-slate-700 mb-1">Project</label>
        <select
          className="block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none max-w-xs"
          value={selectedProject?.id ?? ''}
          onChange={(e) => {
            const p = projects.find((x) => x.id === e.target.value) ?? null;
            setSelectedProject(p);
            setSelectedApp(null);
            setApps([]);
          }}
        >
          <option value="">Select a project…</option>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} ({p.slug})
            </option>
          ))}
        </select>
      </div>

      {selectedProject && (
        <>
          <Modal
            isOpen={showCreateForm}
            onClose={() => setShowCreateForm(false)}
            title="New Application"
          >
            <CreateAppForm
              project={selectedProject}
              onCreated={() => {
                setShowCreateForm(false);
                void loadApps(selectedProject.id);
              }}
              onCancel={() => setShowCreateForm(false)}
              onElevationRequired={onElevationRequired}
            />
          </Modal>

          {loading && <p className="text-sm text-slate-500">Loading…</p>}
          {!loading && apps.length === 0 && (
            <div className="rounded-xl border border-slate-200 bg-white p-12 shadow-sm flex flex-col items-center gap-3 text-center">
              <span className="text-4xl">📦</span>
              <h3 className="text-sm font-semibold text-slate-900">No applications yet</h3>
              <p className="text-sm text-slate-500">Create one to get started with deployments.</p>
            </div>
          )}
          {!loading && apps.length > 0 && (
            <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">App</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Runtime</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {apps.map((app) => {
                    const st = mapAppState(app);
                    const pill =
                      st === 'Healthy' ? 'bg-emerald-50 text-emerald-700' :
                      st === 'Warning' ? 'bg-amber-50 text-amber-700' :
                      st === 'Critical' ? 'bg-red-50 text-red-700' :
                      'bg-slate-100 text-slate-600';
                    const runtimeBadge =
                      app.runtime_type === 'node' ? 'bg-green-50 text-green-700' :
                      app.runtime_type === 'bun' ? 'bg-orange-50 text-orange-700' :
                      app.runtime_type === 'python' ? 'bg-blue-50 text-blue-700' :
                      app.runtime_type === 'php' ? 'bg-purple-50 text-purple-700' :
                      'bg-slate-100 text-slate-600';
                    return (
                      <tr key={app.id} className="hover:bg-slate-50 cursor-pointer" onClick={() => selectApp(app)}>
                        <td className="px-4 py-3 text-sm text-slate-800">
                          <span className="font-medium text-slate-900">{app.name}</span>
                          <span className="ml-2 text-xs text-slate-400">{app.slug}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${runtimeBadge}`}>
                            {app.runtime_type}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${pill}`}>
                            {st}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <button
                            className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-all"
                            onClick={(e) => { e.stopPropagation(); selectApp(app); }}
                          >
                            Manage
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// --- Create App Form --------------------------------------------------------

interface CreateAppFormProps {
  project: Project;
  onCreated: () => void;
  onCancel: () => void;
  onElevationRequired: (action: () => Promise<void>) => void;
}

function CreateAppForm({ project, onCreated, onCancel, onElevationRequired }: CreateAppFormProps) {
  const [servers, setServers] = useState<{ id: string; name: string }[]>([]);
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  const [serverID, setServerID] = useState('');
  const [runtime, setRuntime] = useState('node');
  const [gitUrl, setGitUrl] = useState('');
  const [startProgram, setStartProgram] = useState('node');
  const [startArgs, setStartArgs] = useState('');
  const [port, setPort] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    void api.listServers().then((d) => setServers(d.servers.filter((s) => s.status === 'active')));
  }, []);

  const submit = async () => {
    setSaving(true);
    setError(null);
    try {
      await primeCsrf();
      await api.createApp(project.id, {
        slug: slug.trim(),
        name: name.trim(),
        server_id: serverID,
        runtime_type: runtime,
        git_repo_url: gitUrl.trim(),
        start_program: startProgram.trim() || undefined,
        start_args: startArgs.trim() ? startArgs.trim().split(/\s+/) : undefined,
        port: port.trim() ? parseInt(port, 10) : undefined,
      });
      goeyToast.success('App created');
      onCreated();
    } catch (e: unknown) {
      if (isStepUpRequired(e)) {
        onElevationRequired(() => submit());
      } else {
        const err = toError(e);
        goeyToast.error(`Failed: ${err.message}`);
        setError(err);
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      {error && <ErrorNote error={error} />}
      <div className="grid grid-cols-2 gap-3">
        <Field label="Slug">
          <input className={inputClass} value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="my-app" />
        </Field>
        <Field label="Name">
          <input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} placeholder="My App" />
        </Field>
        <Field label="Server">
          <select className={inputClass} value={serverID} onChange={(e) => setServerID(e.target.value)}>
            <option value="">Select server…</option>
            {servers.map((s) => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>
        </Field>
        <Field label="Runtime">
          <select className={inputClass} value={runtime} onChange={(e) => setRuntime(e.target.value)}>
            <option value="node">Node.js</option>
            <option value="bun">Bun</option>
            <option value="python">Python</option>
            <option value="php">PHP</option>
            <option value="static">Static</option>
          </select>
        </Field>
        <div className="col-span-2">
          <Field label="Git Repo URL">
            <input className={inputClass} value={gitUrl} onChange={(e) => setGitUrl(e.target.value)} placeholder="https://github.com/org/repo.git" />
          </Field>
        </div>
        <Field label="Start Program">
          <input className={inputClass} value={startProgram} onChange={(e) => setStartProgram(e.target.value)} placeholder="node" />
        </Field>
        <Field label="Start Args (space-separated)">
          <input className={inputClass} value={startArgs} onChange={(e) => setStartArgs(e.target.value)} placeholder="dist/index.js" />
        </Field>
        <Field label="Port">
          <input className={inputClass} value={port} onChange={(e) => setPort(e.target.value)} placeholder="3000" />
        </Field>
      </div>
      <div className="flex gap-2">
        <button className={primaryButtonClass} onClick={() => void submit()} disabled={saving || !slug || !name || !serverID || !gitUrl}>
          {saving ? 'Creating…' : 'Create App'}
        </button>
        <button className={secondaryButtonClass} onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}

// --- App Detail -------------------------------------------------------------

type AppTab = 'deploy' | 'env' | 'webhooks' | 'previews';

interface AppDetailProps {
  app: App;
  project: Project;
  onBack: () => void;
  onDeleted: () => void;
  onElevationRequired: (action: () => Promise<void>) => void;
}

function AppDetail({ app, project, onBack, onDeleted, onElevationRequired }: AppDetailProps) {
  const [tab, setTab] = useState<AppTab>('deploy');
  const [deleting, setDeleting] = useState(false);
  const [confirmState, setConfirmState] = useState<{ open: boolean; message: string; onConfirm: () => void }>({ open: false, message: '', onConfirm: () => {} });

  const tabClass = (t: AppTab) =>
    `px-4 py-1.5 text-sm rounded-md ${tab === t ? 'bg-elevated font-medium text-ink' : 'text-ink-secondary hover:text-ink'}`;

  const handleDelete = async () => {
    setConfirmState({
      open: true,
      message: `Delete application "${app.name}"?`,
      onConfirm: async () => {
        setDeleting(true);
        try {
          await primeCsrf();
          await api.deleteApp(project.id, app.id);
          goeyToast.success('App deleted');
          onDeleted();
        } catch (e: unknown) {
          if (isStepUpRequired(e)) {
            onElevationRequired(() => handleDelete());
          } else {
            const err = toError(e);
            goeyToast.error(`Failed: ${err.message}`);
          }
        } finally {
          setDeleting(false);
        }
      },
    });
  };

  return (
    <section className="px-6 py-8">
      <ConfirmModal
        isOpen={confirmState.open}
        onClose={() => setConfirmState(s => ({ ...s, open: false }))}
        onConfirm={confirmState.onConfirm}
        title="Are you sure?"
        message={confirmState.message}
        confirmLabel="Yes, proceed"
        danger
      />
      <div className="flex items-center justify-between mb-4">
        <button className="text-sm text-ink-secondary hover:text-ink" onClick={onBack}>
          ← Back to Apps
        </button>
        <button
          className="text-xs text-red-500 hover:text-red-700 underline"
          onClick={() => void handleDelete()}
          disabled={deleting}
        >
          {deleting ? 'Deleting…' : 'Delete App'}
        </button>
      </div>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-xl font-semibold text-ink">{app.name}</h1>
          <p className="text-sm text-ink-muted">{app.runtime_type} · {app.slug} · {app.git_repo_url}</p>
        </div>
        <StatusBadge state={mapAppState(app)} />
      </div>
      <nav className="flex gap-1 mb-4">
        <button className={tabClass('deploy')} onClick={() => setTab('deploy')}>Deployments</button>
        <button className={tabClass('env')} onClick={() => setTab('env')}>Env Vars</button>
        <button className={tabClass('webhooks')} onClick={() => setTab('webhooks')}>Webhooks</button>
        <button className={tabClass('previews')} onClick={() => setTab('previews')}>PR Previews</button>
      </nav>
      {tab === 'deploy' && (
        <DeployTab app={app} project={project} onElevationRequired={onElevationRequired} />
      )}
      {tab === 'env' && (
        <EnvTab app={app} project={project} onElevationRequired={onElevationRequired} />
      )}
      {tab === 'webhooks' && (
        <WebhooksTab app={app} project={project} onElevationRequired={onElevationRequired} />
      )}
      {tab === 'previews' && (
        <PreviewsTab app={app} project={project} onElevationRequired={onElevationRequired} />
      )}
    </section>
  );
}

// --- Deploy Tab -------------------------------------------------------------

function DeployTab({
  app,
  project,
  onElevationRequired,
}: {
  app: App;
  project: Project;
  onElevationRequired: (action: () => Promise<void>) => void;
}) {
  const [commitSHA, setCommitSHA] = useState('');
  const [gitRef, setGitRef] = useState(app.git_ref_default || 'main');
  const [deploying, setDeploying] = useState(false);
  const [deployError, setDeployError] = useState<Error | null>(null);
  const [deployResult, setDeployResult] = useState<DeployAccepted | null>(null);
  const [job, setJob] = useState<JobStatus | null>(null);
  const [deployments, setDeployments] = useState<Deployment[]>([]);
  const [releases, setReleases] = useState<Release[]>([]);
  const [listError, setListError] = useState<Error | null>(null);
  const [rollingBack, setRollingBack] = useState(false);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const loadHistory = useCallback(async () => {
    try {
      const [deps, rels] = await Promise.all([
        api.listDeployments(project.id, app.id, { limit: 10 }),
        api.listReleases(project.id, app.id),
      ]);
      setDeployments(deps.deployments);
      setReleases(rels.releases);
    } catch (e: unknown) {
      setListError(toError(e));
    }
  }, [project.id, app.id]);

  useEffect(() => {
    void loadHistory();
  }, [loadHistory]);

  useEffect(() => {
    return () => {
      if (pollRef.current !== null) clearTimeout(pollRef.current);
    };
  }, []);

  const pollJob = useCallback(async (jobId: string) => {
    try {
      const status = await api.getJob(jobId);
      setJob(status);
      if (!JOB_TERMINAL.has(status.job.state)) {
        pollRef.current = setTimeout(() => void pollJob(jobId), 2000);
      } else {
        void loadHistory();
      }
    } catch {
      pollRef.current = setTimeout(() => void pollJob(jobId), 3000);
    }
  }, [loadHistory]);

  const triggerDeploy = async () => {
    setDeploying(true);
    setDeployError(null);
    setDeployResult(null);
    setJob(null);
    try {
      await primeCsrf();
      const result = await api.deployApp(project.id, app.id, {
        commit_sha: commitSHA.trim(),
        git_ref: gitRef.trim() || undefined,
      });
      goeyToast.success('Deployment triggered');
      setDeployResult(result);
      void pollJob(result.job.id);
    } catch (e: unknown) {
      if (isStepUpRequired(e)) {
        onElevationRequired(() => triggerDeploy());
      } else {
        const err = toError(e);
        goeyToast.error(`Failed: ${err.message}`);
        setDeployError(err);
      }
    } finally {
      setDeploying(false);
    }
  };

  const triggerRollback = async () => {
    setRollingBack(true);
    setDeployError(null);
    try {
      await primeCsrf();
      const result = await api.rollbackApp(project.id, app.id);
      goeyToast.success('Rollback triggered');
      setDeployResult(result);
      void pollJob(result.job.id);
    } catch (e: unknown) {
      if (isStepUpRequired(e)) {
        onElevationRequired(() => triggerRollback());
      } else {
        const err = toError(e);
        goeyToast.error(`Failed: ${err.message}`);
        setDeployError(err);
      }
    } finally {
      setRollingBack(false);
    }
  };

  const triggerRedeploy = async (depId: string) => {
    setDeployError(null);
    try {
      await primeCsrf();
      const result = await api.redeployApp(project.id, app.id, depId);
      goeyToast.success('Redeployment triggered');
      setDeployResult(result);
      void pollJob(result.job.id);
    } catch (e: unknown) {
      if (isStepUpRequired(e)) {
        onElevationRequired(() => triggerRedeploy(depId));
      } else {
        const err = toError(e);
        goeyToast.error(`Failed: ${err.message}`);
        setDeployError(err);
      }
    }
  };

  const shaOk = /^[0-9a-f]{7,40}$/.test(commitSHA.trim());

  return (
    <div className="space-y-6">
      {/* Trigger form */}
      <div className="rounded-lg border border-line bg-surface p-4 space-y-3">
        <h3 className="font-medium text-ink">Trigger Deployment</h3>
        {deployError && <ErrorNote error={deployError} />}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Commit SHA (7–40 hex chars)">
            <input
              className={`${inputClass} font-mono`}
              value={commitSHA}
              onChange={(e) => setCommitSHA(e.target.value)}
              placeholder="abc1234"
            />
          </Field>
          <Field label="Git Ref (branch/tag)">
            <input
              className={inputClass}
              value={gitRef}
              onChange={(e) => setGitRef(e.target.value)}
              placeholder="main"
            />
          </Field>
        </div>
        <div className="flex gap-2">
          <button
            className={primaryButtonClass}
            onClick={() => void triggerDeploy()}
            disabled={deploying || !shaOk}
          >
            {deploying ? 'Deploying…' : 'Deploy'}
          </button>
          {releases.some((r) => !r.is_current) && (
            <button
              className={secondaryButtonClass}
              onClick={() => void triggerRollback()}
              disabled={rollingBack}
            >
              {rollingBack ? 'Rolling back…' : 'Rollback'}
            </button>
          )}
        </div>
        {deployResult && (
          <p className="text-sm text-ink-secondary">
            Deployment <code className="font-mono">{deployResult.deployment_id.slice(0, 8)}</code> enqueued.
          </p>
        )}
      </div>

      {/* Active job progress */}
      {job && <JobProgress job={job} />}

      {/* Releases */}
      {releases.length > 0 && (
        <div>
          <h3 className="font-medium text-ink mb-2">Releases</h3>
          <ul className="space-y-1">
            {releases.map((r) => (
              <li key={r.id} className="flex items-center justify-between rounded-md border border-line bg-surface px-3 py-2 text-sm">
                <div>
                  <code className="font-mono text-ink-muted">{r.commit_sha.slice(0, 10)}</code>
                  {r.is_current && (
                    <span className="ml-2 rounded bg-green-100 px-1.5 py-0.5 text-xs text-green-700">current</span>
                  )}
                </div>
                <span className="text-ink-muted">{formatTs(r.created_at)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Deployment history */}
      <div>
        <h3 className="font-medium text-ink mb-2">Deployment History</h3>
        {listError && <ErrorNote error={listError} />}
        {deployments.length === 0 && !listError && (
          <EmptyState title="No deployments yet">
            Trigger a deployment above to begin.
          </EmptyState>
        )}
        {deployments.length > 0 && (
          <ul className="space-y-2">
            {deployments.map((d) => (
              <li key={d.id} className="rounded-lg border border-line bg-surface p-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <StatusBadge state={mapDeployState(d.state)} />
                    <span className="text-sm font-medium text-ink">{d.trigger}</span>
                    {d.commit_sha && (
                      <code className="text-xs font-mono text-ink-muted">{d.commit_sha.slice(0, 10)}</code>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-ink-muted">{formatTs(d.created_at)}</span>
                    {d.commit_sha && (
                      <button
                        className="text-xs text-ink-secondary hover:text-ink underline"
                        onClick={() => void triggerRedeploy(d.id)}
                      >
                        Redeploy
                      </button>
                    )}
                  </div>
                </div>
                {d.error_summary && (
                  <p className="mt-1 text-xs text-red-600">{d.error_summary}</p>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

// --- Job Progress -----------------------------------------------------------

function jobStateLabel(state: string): OperationalState {
  if (state === 'succeeded') return 'Healthy';
  if (state === 'running') return 'Pending';
  if (state === 'queued') return 'Pending';
  if (state === 'failed' || state === 'dead_letter') return 'Critical';
  return 'Disabled';
}

function JobProgress({ job }: { job: JobStatus }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-medium text-ink">Job Progress</h3>
        <StatusBadge state={jobStateLabel(job.job.state)} />
      </div>
      {job.steps.length > 0 && (
        <ul className="space-y-1">
          {job.steps.map((s) => (
            <li key={s.index} className="flex items-center gap-2 text-sm">
              <StatusBadge state={jobStateLabel(s.state)} />
              <span className="font-medium text-ink">{s.name}</span>
              {s.error_summary && <span className="text-red-600 text-xs">- {s.error_summary}</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// --- Env Tab ----------------------------------------------------------------

function EnvTab({
  app,
  project,
  onElevationRequired,
}: {
  app: App;
  project: Project;
  onElevationRequired: (action: () => Promise<void>) => void;
}) {
  const [envVars, setEnvVars] = useState<EnvVar[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [newName, setNewName] = useState('');
  const [newSource, setNewSource] = useState<'literal' | 'secret_ref'>('literal');
  const [newValue, setNewValue] = useState('');
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.listEnvVars(project.id, app.id);
      setEnvVars(data.env_vars);
    } catch (e: unknown) {
      setError(toError(e));
    } finally {
      setLoading(false);
    }
  }, [project.id, app.id]);

  useEffect(() => { void load(); }, [load]);

  const addEnvVar = async () => {
    setSaving(true);
    setError(null);
    try {
      await primeCsrf();
      await api.setEnvVar(project.id, app.id, {
        name: newName.trim(),
        value_source: newSource,
        value: newValue.trim(),
      });
      goeyToast.success(`Environment variable ${newName.trim()} saved`);
      setNewName(''); setNewValue(''); setShowAdd(false);
      void load();
    } catch (e: unknown) {
      if (isStepUpRequired(e)) {
        onElevationRequired(() => addEnvVar());
      } else {
        const err = toError(e);
        goeyToast.error(`Failed: ${err.message}`);
        setError(err);
      }
    } finally {
      setSaving(false);
    }
  };

  const deleteEnvVar = async (name: string) => {
    try {
      await primeCsrf();
      await api.deleteEnvVar(project.id, app.id, name);
      goeyToast.success(`Environment variable ${name} deleted`);
      void load();
    } catch (e: unknown) {
      if (isStepUpRequired(e)) {
        onElevationRequired(() => deleteEnvVar(name));
      } else {
        const err = toError(e);
        goeyToast.error(`Failed: ${err.message}`);
        setError(err);
      }
    }
  };

  return (
    <div className="space-y-4">
      {error && <ErrorNote error={error} />}
      <div className="flex justify-end">
        <button className={secondaryButtonClass} onClick={() => setShowAdd(true)}>+ Add Variable</button>
      </div>
      <Modal
        isOpen={showAdd}
        onClose={() => setShowAdd(false)}
        title="Add Environment Variable"
      >
        <div className="space-y-4">
          {error && <ErrorNote error={error} />}
          <div className="grid grid-cols-1 gap-3">
            <Field label="Name">
              <input className={inputClass} value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="PORT" />
            </Field>
            <Field label="Source">
              <select className={inputClass} value={newSource} onChange={(e) => setNewSource(e.target.value as 'literal' | 'secret_ref')}>
                <option value="literal">Literal</option>
                <option value="secret_ref">Secret ref</option>
              </select>
            </Field>
            <Field label={newSource === 'literal' ? 'Value' : 'secret:// URI'}>
              <input className={inputClass} value={newValue} onChange={(e) => setNewValue(e.target.value)} placeholder={newSource === 'literal' ? '3000' : 'secret://app/db-pass'} />
            </Field>
          </div>
          <div className="flex gap-2 justify-end pt-2">
            <button className={secondaryButtonClass} onClick={() => setShowAdd(false)}>Cancel</button>
            <button className={primaryButtonClass} onClick={() => void addEnvVar()} disabled={saving || !newName || !newValue}>{saving ? 'Saving…' : 'Save'}</button>
          </div>
        </div>
      </Modal>
      {loading && <p className="text-ink-secondary text-sm">Loading…</p>}
      {!loading && envVars.length === 0 && (
        <EmptyState title="No environment variables">
          Add variables or secret references above.
        </EmptyState>
      )}
      {envVars.length > 0 && (
        <ul className="space-y-1">
          {envVars.map((ev) => (
            <li key={ev.name} className="flex items-center justify-between rounded-md border border-line bg-surface px-3 py-2 text-sm">
              <div>
                <code className="font-mono font-medium text-ink">{ev.name}</code>
                {ev.value_source === 'literal' && ev.value !== undefined && (
                  <span className="ml-2 text-ink-muted">{ev.value}</span>
                )}
                {ev.value_source === 'secret_ref' && (
                  <span className="ml-2 text-ink-muted italic">secret ref</span>
                )}
              </div>
              <button
                className="text-xs text-red-500 hover:text-red-700 underline"
                onClick={() => void deleteEnvVar(ev.name)}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// --- Webhooks Tab -----------------------------------------------------------

function WebhooksTab({
  app,
  project,
  onElevationRequired,
}: {
  app: App;
  project: Project;
  onElevationRequired: (action: () => Promise<void>) => void;
}) {
  const [tokens, setTokens] = useState<WebhookToken[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [newToken, setNewToken] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.listWebhookTokens(project.id, app.id);
      setTokens(data.webhook_tokens);
    } catch (e: unknown) {
      setError(toError(e));
    } finally {
      setLoading(false);
    }
  }, [project.id, app.id]);

  useEffect(() => { void load(); }, [load]);

  const createToken = async () => {
    setCreating(true);
    setError(null);
    setNewToken(null);
    try {
      await primeCsrf();
      const result = await api.createWebhookToken(project.id, app.id);
      goeyToast.success('Webhook token created');
      setNewToken(result.token);
      void load();
    } catch (e: unknown) {
      if (isStepUpRequired(e)) {
        onElevationRequired(() => createToken());
      } else {
        const err = toError(e);
        goeyToast.error(`Failed: ${err.message}`);
        setError(err);
      }
    } finally {
      setCreating(false);
    }
  };

  const revokeToken = async (tokenId: string) => {
    setError(null);
    try {
      await primeCsrf();
      await api.revokeWebhookToken(project.id, app.id, tokenId);
      goeyToast.success('Webhook token revoked');
      void load();
    } catch (e: unknown) {
      if (isStepUpRequired(e)) {
        onElevationRequired(() => revokeToken(tokenId));
      } else {
        const err = toError(e);
        goeyToast.error(`Failed: ${err.message}`);
        setError(err);
      }
    }
  };

  const webhookURL = (raw: string) =>
    `${window.location.origin}/api/v1/webhooks/git/${encodeURIComponent(raw)}`;

  return (
    <div className="space-y-4">
      {error && <ErrorNote error={error} />}

      {newToken && (
        <div className="rounded-lg border border-amber-300 bg-amber-50 p-4">
          <p className="text-sm font-medium text-amber-900 mb-1">
            Copy this webhook token now - it will not be shown again.
          </p>
          <code className="block font-mono text-xs break-all text-amber-800 bg-amber-100 rounded p-2 mb-2">
            {newToken}
          </code>
          <p className="text-xs text-amber-700 mb-1">Webhook URL:</p>
          <code className="block font-mono text-xs break-all text-amber-800 bg-amber-100 rounded p-2">
            {webhookURL(newToken)}
          </code>
          <p className="text-xs text-amber-600 mt-2">
            Configure this URL as a push webhook in GitHub/GitLab. Set Content-Type: application/json.
          </p>
        </div>
      )}

      <div className="flex justify-end">
        <button className={secondaryButtonClass} onClick={() => void createToken()} disabled={creating}>
          {creating ? 'Generating…' : '+ New Webhook Token'}
        </button>
      </div>

      {loading && <p className="text-ink-secondary text-sm">Loading…</p>}
      {!loading && tokens.length === 0 && (
        <EmptyState title="No webhook tokens">
          Create one to enable push-triggered deployments.
        </EmptyState>
      )}
      {tokens.length > 0 && (
        <ul className="space-y-2">
          {tokens.map((t) => (
            <li key={t.id} className="flex items-center justify-between rounded-md border border-line bg-surface px-3 py-2 text-sm">
              <div>
                <code className="font-mono text-xs text-ink-muted">{t.id.slice(0, 16)}…</code>
                <span className={`ml-2 text-xs ${t.state === 'active' ? 'text-green-700' : 'text-ink-muted'}`}>
                  {t.state}
                </span>
                {t.last_used_at && (
                  <span className="ml-2 text-xs text-ink-muted">last used {formatTs(t.last_used_at)}</span>
                )}
              </div>
              {t.state === 'active' && (
                <button
                  className="text-xs text-red-500 hover:text-red-700 underline"
                  onClick={() => void revokeToken(t.id)}
                >
                  Revoke
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// --- Previews Tab (PRD §11.6) ------------------------------------------------

interface PreviewsTabProps {
  app: App;
  project: Project;
  onElevationRequired: (action: () => Promise<void>) => void;
}

interface PreviewItem {
  id: string;
  app_id: string;
  branch: string;
  pr_number?: number;
  preview_url: string;
  status: string;
  created_at: string;
}

function PreviewsTab({ app, project, onElevationRequired }: PreviewsTabProps) {
  const [previews, setPreviews] = useState<PreviewItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [branch, setBranch] = useState('');
  const [prNumber, setPrNumber] = useState('');
  const [creating, setCreating] = useState(false);
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [confirmState, setConfirmState] = useState<{ open: boolean; message: string; onConfirm: () => void }>({ open: false, message: '', onConfirm: () => {} });

  const loadPreviews = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.listPreviews(project.id, app.id);
      setPreviews(res.previews || []);
    } catch (e: unknown) {
      setError(toError(e));
    } finally {
      setLoading(false);
    }
  }, [project.id, app.id]);

  useEffect(() => {
    void loadPreviews();
  }, [loadPreviews]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!branch.trim()) return;
    setCreating(true);
    setError(null);
    const run = async () => {
      try {
        await primeCsrf();
        const pr = prNumber ? parseInt(prNumber, 10) : undefined;
        await api.createPreview(project.id, app.id, { branch: branch.trim(), pr_number: pr });
        goeyToast.success('Preview environment created');
        setBranch('');
        setPrNumber('');
        setIsCreateOpen(false);
        await loadPreviews();
      } catch (err: unknown) {
        if (isStepUpRequired(err)) {
          onElevationRequired(run);
          return;
        }
        const e = toError(err);
        goeyToast.error(`Failed: ${e.message}`);
        setError(e);
      } finally {
        setCreating(false);
      }
    };
    await run();
  };

  const handleTeardown = async (previewId: string) => {
    setConfirmState({
      open: true,
      message: 'Tear down this ephemeral preview environment?',
      onConfirm: async () => {
        const run = async () => {
          try {
            await primeCsrf();
            await api.deletePreview(project.id, app.id, previewId);
            goeyToast.success('Preview environment torn down');
            await loadPreviews();
          } catch (err: unknown) {
            if (isStepUpRequired(err)) {
              onElevationRequired(run);
              return;
            }
            const e = toError(err);
            goeyToast.error(`Failed: ${e.message}`);
            setError(e);
          }
        };
        await run();
      },
    });
  };

  return (
    <div className="space-y-6">
      <ConfirmModal
        isOpen={confirmState.open}
        onClose={() => setConfirmState(s => ({ ...s, open: false }))}
        onConfirm={confirmState.onConfirm}
        title="Are you sure?"
        message={confirmState.message}
        confirmLabel="Yes, proceed"
        danger
      />
      <div className="rounded-lg border border-line bg-surface p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-ink">PR & Branch Preview Environments</h3>
          <p className="text-xs text-ink-muted mt-1">
            Deploy ephemeral branch-isolated testing environments with dedicated routing and automatic teardown.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setIsCreateOpen(true)}
          className={primaryButtonClass}
        >
          + Deploy Preview
        </button>
      </div>

      <Modal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        title="Deploy Preview Environment"
      >
        <div className="space-y-4">
          {error && <ErrorNote error={error} onRetry={() => setError(null)} />}
          <form onSubmit={handleCreate} className="space-y-3">
            <Field label="Git Branch">
              <input
                type="text"
                required
                placeholder="feat/preview-test"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                className={inputClass}
              />
            </Field>
            <Field label="Pull Request # (Optional)">
              <input
                type="number"
                placeholder="42"
                value={prNumber}
                onChange={(e) => setPrNumber(e.target.value)}
                className={inputClass}
              />
            </Field>
            <div className="flex gap-2 justify-end pt-2">
              <button
                type="button"
                onClick={() => setIsCreateOpen(false)}
                className={secondaryButtonClass}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={creating || !branch.trim()}
                className={primaryButtonClass}
              >
                {creating ? 'Spawning Preview…' : 'Deploy Preview'}
              </button>
            </div>
          </form>
        </div>
      </Modal>

      <div className="space-y-3">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
          Active Preview Environments ({previews.length})
        </h4>

        {loading ? (
          <p className="text-xs text-ink-muted">Loading previews…</p>
        ) : previews.length === 0 ? (
          <div className="rounded-lg border border-dashed border-line p-6 text-center text-sm text-ink-muted">
            No active ephemeral preview environments. Deploy a branch above to create one.
          </div>
        ) : (
          <div className="space-y-2">
            {previews.map((p) => (
              <div
                key={p.id}
                className="flex items-center justify-between rounded-lg border border-line bg-surface p-3 text-sm"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-semibold text-ink bg-canvas px-2 py-0.5 rounded border border-line">
                      {p.branch}
                    </span>
                    {p.pr_number && (
                      <span className="text-xs text-primary font-medium">PR #{p.pr_number}</span>
                    )}
                    <span className="text-xs text-emerald-600 bg-emerald-500/10 px-1.5 py-0.5 rounded">
                      {p.status}
                    </span>
                  </div>
                  <div>
                    <a
                      href={p.preview_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-primary hover:underline font-mono"
                    >
                      {p.preview_url} ↗
                    </a>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => void handleTeardown(p.id)}
                  className="text-xs px-2.5 py-1 rounded bg-rose-500/10 text-rose-500 hover:bg-rose-500/20 transition font-medium"
                >
                  Teardown
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

