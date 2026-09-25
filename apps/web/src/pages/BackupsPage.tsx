import { useCallback, useEffect, useState } from 'react';

import {
  api,
  isStepUpRequired,
  type BackupLinkCreated,
  type BackupPlan,
  type BackupRun,
  type Project,
  type Server,
} from '../api/client';
import { StepUpPrompt } from '../components/StepUpPrompt';
import {
  EmptyState,
  ErrorNote,
  Field,
  StatusBadge,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
  type OperationalState,
} from '../components/ui';

function mapPlanState(plan: BackupPlan): OperationalState {
  if (plan.state === 'active' && plan.enabled) return 'Healthy';
  if (plan.state === 'pending_delete') return 'Warning';
  if (plan.state === 'suspended' || !plan.enabled) return 'Warning';
  return 'Disabled';
}

function mapRunState(run: BackupRun): OperationalState {
  if (run.state === 'completed') return 'Healthy';
  if (run.state === 'running' || run.state === 'queued') return 'Warning';
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

function formatBytes(n: number): string {
  if (!n) return '-';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function toError(e: unknown): Error {
  return e instanceof Error ? e : new Error(String(e));
}

export function BackupsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [servers, setServers] = useState<Server[]>([]);
  const [plans, setPlans] = useState<BackupPlan[]>([]);
  const [runs, setRuns] = useState<BackupRun[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [stepUpPending, setStepUpPending] = useState(false);
  const [stepUpAction, setStepUpAction] = useState<(() => Promise<void>) | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [tab, setTab] = useState<'plans' | 'runs'>('plans');
  const [jobMsg, setJobMsg] = useState<string | null>(null);
  const [createdLink, setCreatedLink] = useState<BackupLinkCreated | null>(null);
  const [copied, setCopied] = useState(false);

  const [newPlan, setNewPlan] = useState({
    server_id: '',
    name: '',
    slug: '',
    scope_type: 'project',
    destination_type: 'local',
    base_dir: '',
    schedule_cron: '',
    retention_count: 7,
    retention_days: 30,
  });

  const loadProjects = useCallback(async () => {
    try {
      const data = await api.listProjects({ state: 'active', limit: 50 });
      setProjects(data.projects || []);
    } catch (e: unknown) {
      setError(toError(e));
    }
  }, []);

  const loadServers = useCallback(async () => {
    try {
      const data = await api.listServers();
      setServers(data.servers || []);
    } catch (e: unknown) {
      setError(toError(e));
    }
  }, []);

  const loadPlans = useCallback(async (projectId: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listBackupPlans(projectId);
      setPlans(data.plans || []);
    } catch (e: unknown) {
      setError(toError(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadRuns = useCallback(async (projectId: string) => {
    try {
      const data = await api.listBackupRuns(projectId);
      setRuns(data.runs || []);
    } catch (e: unknown) {
      setError(toError(e));
    }
  }, []);

  useEffect(() => {
    void loadProjects();
    void loadServers();
  }, [loadProjects, loadServers]);

  useEffect(() => {
    if (selectedProject) {
      void loadPlans(selectedProject.id);
      void loadRuns(selectedProject.id);
    }
  }, [selectedProject, loadPlans, loadRuns]);

  const onElevationRequired = (action: () => Promise<void>) => {
    setStepUpAction(() => action);
    setStepUpPending(true);
  };

  const handleCreatePlan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProject) return;
    setError(null);
    try {
      await api.createBackupPlan(selectedProject.id, {
        server_id: newPlan.server_id,
        name: newPlan.name,
        slug: newPlan.slug,
        scope_type: newPlan.scope_type,
        destination_type: newPlan.destination_type,
        destination_config:
          newPlan.destination_type === 'local' && newPlan.base_dir
            ? { base_dir: newPlan.base_dir }
            : undefined,
        schedule_cron: newPlan.schedule_cron || undefined,
        retention_count: newPlan.retention_count,
        retention_days: newPlan.retention_days,
      });
      setShowCreateForm(false);
      setNewPlan({
        server_id: '',
        name: '',
        slug: '',
        scope_type: 'project',
        destination_type: 'local',
        base_dir: '',
        schedule_cron: '',
        retention_count: 7,
        retention_days: 30,
      });
      await loadPlans(selectedProject.id);
    } catch (err: unknown) {
      setError(toError(err));
    }
  };

  const handleDeletePlan = async (plan: BackupPlan) => {
    if (!selectedProject) return;
    if (!window.confirm(`Delete backup plan "${plan.name}"? It enters a soft-delete grace period.`)) {
      return;
    }
    const run = async () => {
      try {
        await api.deleteBackupPlan(selectedProject.id, plan.id);
        await loadPlans(selectedProject.id);
      } catch (err: unknown) {
        if (isStepUpRequired(err)) {
          onElevationRequired(run);
          return;
        }
        setError(toError(err));
      }
    };
    await run();
  };

  const handleTriggerRun = async (plan: BackupPlan) => {
    if (!selectedProject) return;
    setJobMsg(null);
    try {
      const res = await api.triggerBackupRun(selectedProject.id, plan.id);
      setJobMsg(`Backup queued (run ${res.run_id}, job ${res.job_id}).`);
      await loadRuns(selectedProject.id);
      setTab('runs');
    } catch (err: unknown) {
      setError(toError(err));
    }
  };

  const handleVerify = async (run: BackupRun) => {
    if (!selectedProject) return;
    setJobMsg(null);
    try {
      const res = await api.verifyBackupRun(selectedProject.id, run.id);
      setJobMsg(`Verification queued (job ${res.job_id}).`);
    } catch (err: unknown) {
      setError(toError(err));
    }
  };

  const handleRestore = async (run: BackupRun) => {
    if (!selectedProject) return;
    if (!window.confirm('Restore this backup? Existing files at the destination will be overwritten.')) {
      return;
    }
    const go = async () => {
      try {
        const res = await api.restoreBackupRun(selectedProject.id, run.id);
        setJobMsg(`Restore queued (job ${res.job_id}).`);
      } catch (err: unknown) {
        if (isStepUpRequired(err)) {
          onElevationRequired(go);
          return;
        }
        setError(toError(err));
      }
    };
    await go();
  };

  const handleDeleteRun = async (run: BackupRun) => {
    if (!selectedProject) return;
    if (!window.confirm('Delete this backup artifact? This cannot be undone.')) return;
    const go = async () => {
      try {
        const res = await api.deleteBackupRun(selectedProject.id, run.id);
        setJobMsg(`Delete queued (job ${res.job_id}).`);
        await loadRuns(selectedProject.id);
      } catch (err: unknown) {
        if (isStepUpRequired(err)) {
          onElevationRequired(go);
          return;
        }
        setError(toError(err));
      }
    };
    await go();
  };

  const handleCreateLink = async (run: BackupRun) => {
    if (!selectedProject) return;
    setCreatedLink(null);
    try {
      const link = await api.createBackupLink(selectedProject.id, run.id);
      setCreatedLink(link);
    } catch (err: unknown) {
      setError(toError(err));
    }
  };

  return (
    <div className="space-y-6">
      {stepUpPending && stepUpAction && (
        <StepUpPrompt
          onElevated={() => {
            setStepUpPending(false);
            const act = stepUpAction;
            setStepUpAction(null);
            void act();
          }}
          onCancel={() => {
            setStepUpPending(false);
            setStepUpAction(null);
          }}
        />
      )}

      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-line pb-4">
        <div>
          <h2 className="text-xl font-semibold text-ink">Backups</h2>
          <p className="text-xs text-ink-muted">
            Scheduled file backups with verified checksums and expiring download links.
          </p>
        </div>
        {selectedProject && tab === 'plans' && (
          <button
            type="button"
            onClick={() => setShowCreateForm(!showCreateForm)}
            className={primaryButtonClass}
          >
            {showCreateForm ? 'Cancel' : 'New Plan'}
          </button>
        )}
      </div>

      {error && <ErrorNote error={error} />}
      {jobMsg && <p className="text-xs text-ink-secondary">{jobMsg}</p>}

      <div className="flex items-center gap-3">
        <label htmlFor="backup-project-select" className="text-xs font-medium text-ink-secondary">
          Project:
        </label>
        <select
          id="backup-project-select"
          value={selectedProject?.id || ''}
          onChange={(e) => {
            const p = projects.find((x) => x.id === e.target.value) || null;
            setSelectedProject(p);
            setCreatedLink(null);
          }}
          className={`${inputClass} max-w-xs`}
        >
          <option value="">Select a project…</option>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} ({p.slug})
            </option>
          ))}
        </select>
      </div>

      {!selectedProject ? (
        <EmptyState title="Select a project">
          Choose an active project to view and manage its backup plans.
        </EmptyState>
      ) : (
        <div className="space-y-4">
          <div className="flex gap-2 border-b border-line pb-2">
            {(['plans', 'runs'] as const).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setTab(t)}
                className={`rounded-md px-3 py-1.5 text-xs font-medium capitalize ${
                  tab === t
                    ? 'bg-elevated font-semibold text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                {t === 'plans' ? 'Plans' : 'Runs'}
              </button>
            ))}
            <button
              type="button"
              onClick={() => {
                if (selectedProject) {
                  void loadPlans(selectedProject.id);
                  void loadRuns(selectedProject.id);
                }
              }}
              className={`${secondaryButtonClass} ml-auto`}
            >
              Refresh
            </button>
          </div>

          {tab === 'plans' && (
            <div className="space-y-4">
              {showCreateForm && (
                <form
                  onSubmit={handleCreatePlan}
                  className="space-y-4 rounded-lg border border-line bg-surface p-4"
                >
                  <h3 className="text-sm font-semibold text-ink">New Backup Plan</h3>
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <Field label="Server">
                      <select
                        required
                        value={newPlan.server_id}
                        onChange={(e) => setNewPlan({ ...newPlan, server_id: e.target.value })}
                        className={inputClass}
                      >
                        <option value="">Select target server…</option>
                        {servers.map((s) => (
                          <option key={s.id} value={s.id}>
                            {s.name} ({s.address})
                          </option>
                        ))}
                      </select>
                    </Field>
                    <Field label="Scope">
                      <select
                        value={newPlan.scope_type}
                        onChange={(e) => setNewPlan({ ...newPlan, scope_type: e.target.value })}
                        className={inputClass}
                      >
                        <option value="project">Project files</option>
                        <option value="site">Site</option>
                        <option value="database">Database</option>
                      </select>
                    </Field>
                    <Field label="Display Name">
                      <input
                        type="text"
                        required
                        placeholder="Nightly backup"
                        value={newPlan.name}
                        onChange={(e) => setNewPlan({ ...newPlan, name: e.target.value })}
                        className={inputClass}
                      />
                    </Field>
                    <Field label="Slug (project unique)">
                      <input
                        type="text"
                        required
                        placeholder="nightly"
                        value={newPlan.slug}
                        onChange={(e) => setNewPlan({ ...newPlan, slug: e.target.value })}
                        className={inputClass}
                      />
                    </Field>
                    <Field label="Destination">
                      <select
                        value={newPlan.destination_type}
                        onChange={(e) =>
                          setNewPlan({ ...newPlan, destination_type: e.target.value })
                        }
                        className={inputClass}
                      >
                        <option value="local">Local disk</option>
                        <option value="s3">S3-compatible</option>
                      </select>
                    </Field>
                    {newPlan.destination_type === 'local' && (
                      <Field label="Base Directory">
                        <input
                          type="text"
                          required
                          placeholder="/var/backups/jawaker"
                          value={newPlan.base_dir}
                          onChange={(e) => setNewPlan({ ...newPlan, base_dir: e.target.value })}
                          className={inputClass}
                        />
                      </Field>
                    )}
                    <Field label="Schedule (5-field cron, optional)">
                      <input
                        type="text"
                        placeholder="0 2 * * *"
                        value={newPlan.schedule_cron}
                        onChange={(e) => setNewPlan({ ...newPlan, schedule_cron: e.target.value })}
                        className={inputClass}
                      />
                    </Field>
                    <Field label="Retention (keep count)">
                      <input
                        type="number"
                        min={1}
                        value={newPlan.retention_count}
                        onChange={(e) =>
                          setNewPlan({ ...newPlan, retention_count: Number(e.target.value) })
                        }
                        className={inputClass}
                      />
                    </Field>
                    <Field label="Retention (days)">
                      <input
                        type="number"
                        min={0}
                        value={newPlan.retention_days}
                        onChange={(e) =>
                          setNewPlan({ ...newPlan, retention_days: Number(e.target.value) })
                        }
                        className={inputClass}
                      />
                    </Field>
                  </div>
                  <div className="flex justify-end gap-2">
                    <button
                      type="button"
                      onClick={() => setShowCreateForm(false)}
                      className={secondaryButtonClass}
                    >
                      Cancel
                    </button>
                    <button type="submit" className={primaryButtonClass}>
                      Create Plan
                    </button>
                  </div>
                </form>
              )}

              {loading ? (
                <p className="text-xs text-ink-muted">Loading plans…</p>
              ) : plans.length === 0 ? (
                <EmptyState title="No backup plans">
                  No backup plans in this project. Create one to get started.
                </EmptyState>
              ) : (
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {plans.map((plan) => (
                    <div
                      key={plan.id}
                      className="space-y-2 rounded-lg border border-line bg-surface p-4"
                    >
                      <div className="flex items-center justify-between">
                        <h4 className="text-sm font-semibold text-ink">{plan.name}</h4>
                        <StatusBadge state={mapPlanState(plan)} detail={plan.state} />
                      </div>
                      <p className="truncate font-mono text-xs text-ink-secondary">{plan.slug}</p>
                      <dl className="space-y-0.5 text-xs text-ink-muted">
                        <div className="flex justify-between">
                          <dt>Scope</dt>
                          <dd className="capitalize text-ink">{plan.scope_type}</dd>
                        </div>
                        <div className="flex justify-between">
                          <dt>Destination</dt>
                          <dd className="uppercase text-ink">{plan.destination_type}</dd>
                        </div>
                        <div className="flex justify-between">
                          <dt>Schedule</dt>
                          <dd className="font-mono text-ink">{plan.schedule_cron || 'manual'}</dd>
                        </div>
                        <div className="flex justify-between">
                          <dt>Next run</dt>
                          <dd className="text-ink">{formatTs(plan.next_run_at)}</dd>
                        </div>
                        <div className="flex justify-between">
                          <dt>Retention</dt>
                          <dd className="text-ink">
                            {plan.retention_count} copies / {plan.retention_days}d
                          </dd>
                        </div>
                      </dl>
                      <div className="flex justify-end gap-2 border-t border-line pt-2">
                        <button
                          type="button"
                          onClick={() => void handleTriggerRun(plan)}
                          className={secondaryButtonClass}
                        >
                          Run now
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleDeletePlan(plan)}
                          className="rounded-md border border-line px-2.5 py-1 text-xs text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20"
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {tab === 'runs' && (
            <div className="space-y-4">
              {createdLink && (
                <div className="space-y-2 rounded-lg border border-line bg-surface p-4">
                  <h4 className="text-sm font-semibold text-ink">Download link created</h4>
                  <p className="text-xs text-ink-muted">
                    Shown once. Expires {formatTs(createdLink.expires_at)}.
                    {createdLink.single_use ? ' Single use.' : ''}
                  </p>
                  <div className="relative">
                    <pre className="overflow-x-auto rounded-md bg-canvas p-3 font-mono text-xs text-ink">
                      {`${window.location.origin}/api/v1/backup-links/${createdLink.token}`}
                    </pre>
                    <button
                      type="button"
                      onClick={() => {
                        void navigator.clipboard.writeText(
                          `${window.location.origin}/api/v1/backup-links/${createdLink.token}`,
                        );
                        setCopied(true);
                        setTimeout(() => setCopied(false), 2000);
                      }}
                      className="absolute right-2 top-2 rounded border border-line bg-surface px-2 py-1 text-xs text-ink-secondary shadow-sm hover:text-ink"
                    >
                      {copied ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                </div>
              )}

              {runs.length === 0 ? (
                <EmptyState title="No backup runs">
                  No runs yet. Trigger a plan to create the first one.
                </EmptyState>
              ) : (
                <div className="divide-y divide-line rounded-lg border border-line bg-surface">
                  {runs.map((run) => (
                    <div key={run.id} className="space-y-2 p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs text-ink">{run.id.slice(0, 8)}</span>
                            <StatusBadge state={mapRunState(run)} detail={run.state} />
                            <span className="text-xs text-ink-muted">{run.trigger}</span>
                          </div>
                          <p className="text-xs text-ink-muted">
                            {formatTs(run.created_at)} &bull; {formatBytes(run.archive_size)} &bull;
                            verification: {run.verification || 'unverified'}
                          </p>
                          {run.failed_reason && (
                            <p className="text-xs text-red-600">{run.failed_reason}</p>
                          )}
                        </div>
                        <div className="flex flex-wrap items-center gap-2">
                          {run.state === 'completed' && (
                            <>
                              <button
                                type="button"
                                onClick={() => void handleVerify(run)}
                                className={secondaryButtonClass}
                              >
                                Verify
                              </button>
                              <button
                                type="button"
                                onClick={() => void handleRestore(run)}
                                className={secondaryButtonClass}
                              >
                                Restore
                              </button>
                              <button
                                type="button"
                                onClick={() => void handleCreateLink(run)}
                                className={secondaryButtonClass}
                              >
                                Link
                              </button>
                            </>
                          )}
                          <button
                            type="button"
                            onClick={() => void handleDeleteRun(run)}
                            className="rounded-md border border-line px-2.5 py-1 text-xs text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20"
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                      {run.sha256 && (
                        <p className="truncate font-mono text-xs text-ink-muted" title={run.sha256}>
                          sha256: {run.sha256}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
