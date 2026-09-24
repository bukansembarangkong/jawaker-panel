import { useEffect, useState } from 'react';
import { type OperationalState, EmptyState, ErrorNote, StatusBadge } from '../components/ui';
import { type CanaryEntry, type ModuleUpdate, type UpdateJob, type UpdateRelease, updatesApi } from '../api/client';

type Tab = 'releases' | 'jobs' | 'modules';

function stateToOperational(state: string): OperationalState {
  const map: Record<string, OperationalState> = {
    done: 'Healthy',
    ready: 'Healthy',
    pass: 'Healthy',
    pending: 'Pending',
    idle: 'Disabled',
    preflight: 'Running',
    downloading: 'Running',
    verifying: 'Running',
    applying: 'Running',
    updating: 'Updating',
    running: 'Running',
    failed: 'Failed',
    rolled_back: 'Warning',
    paused: 'Paused',
  };
  return map[state] ?? 'Unknown';
}

function StateBadge({ state }: { state: string }) {
  return <StatusBadge state={stateToOperational(state)} detail={state} />;
}

function CompatBadge({ compatible }: { compatible: boolean | null }) {
  if (compatible === null) return <StatusBadge state="Unknown" detail="unchecked" />;
  return compatible ? <StatusBadge state="Healthy" detail="compatible" /> : <StatusBadge state="Failed" detail="incompatible" />;
}

// ── Releases tab ───────────────────────────────────────────────────────────────

function ReleasesTab() {
  const [releases, setReleases] = useState<UpdateRelease[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [channel, setChannel] = useState('');
  const [applying, setApplying] = useState<string | null>(null);
  const [fleetRolling, setFleetRolling] = useState<string | null>(null);
  const [fleetMsg, setFleetMsg] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    updatesApi
      .listReleases(channel || undefined)
      .then((r) => setReleases(r.releases ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [channel]); // eslint-disable-line react-hooks/exhaustive-deps

  const runPreflight = async (id: string) => {
    try {
      await updatesApi.runPreflight(id);
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  const applyRelease = async (id: string) => {
    setApplying(id);
    try {
      await updatesApi.applyUpdate(id);
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setApplying(null);
    }
  };

  const runFleetRollout = async (id: string) => {
    setFleetRolling(id);
    setFleetMsg(null);
    try {
      const res = await updatesApi.fleetRollout(id);
      setFleetMsg(`Fleet rollout started: job ${res.job_id.slice(0, 8)}… across ${res.total_nodes} nodes (batch ${res.batch_size}).`);
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setFleetRolling(null);
    }
  };

  if (loading) return <p className="text-ink-secondary text-sm">Loading releases…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load releases" onRetry={load} />;

  return (
    <div className="space-y-4">
      {fleetMsg && (
        <div className="rounded-md border border-emerald-500/30 bg-emerald-500/5 p-2 text-xs text-emerald-600">
          ✓ {fleetMsg}
          <button onClick={() => setFleetMsg(null)} className="ml-2 text-emerald-500 hover:underline">dismiss</button>
        </div>
      )}
      <div className="flex items-center gap-3">
        <select
          value={channel}
          onChange={(e) => setChannel(e.target.value)}
          className="rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-ink"
        >
          <option value="">All channels</option>
          <option value="stable">stable</option>
          <option value="beta">beta</option>
          <option value="edge">edge</option>
        </select>
      </div>

      {releases.length === 0 ? (
        <EmptyState title="No releases discovered">
          <span>Run release discovery to populate this list.</span>
        </EmptyState>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-ink-muted">
                <th className="pb-2 pr-4 font-medium">Version</th>
                <th className="pb-2 pr-4 font-medium">Channel</th>
                <th className="pb-2 pr-4 font-medium">Published</th>
                <th className="pb-2 pr-4 font-medium">Compatible</th>
                <th className="pb-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {releases.map((rel) => (
                <tr key={rel.id}>
                  <td className="py-2 pr-4 font-mono text-xs">{rel.version}</td>
                  <td className="py-2 pr-4">{rel.channel}</td>
                  <td className="py-2 pr-4 text-ink-secondary">{new Date(rel.published_at).toLocaleDateString()}</td>
                  <td className="py-2 pr-4"><CompatBadge compatible={rel.compatible} /></td>
                  <td className="py-2 flex gap-2">
                    {rel.compatible === null && (
                      <button
                        onClick={() => void runPreflight(rel.id)}
                        className="rounded-md border border-border px-2 py-1 text-xs hover:bg-elevated"
                      >
                        Preflight
                      </button>
                    )}
                    {rel.compatible === true && (
                      <button
                        onClick={() => void applyRelease(rel.id)}
                        disabled={applying === rel.id}
                        className="rounded-md bg-accent px-2 py-1 text-xs text-white hover:opacity-90 disabled:opacity-50"
                      >
                        {applying === rel.id ? 'Applying…' : 'Apply'}
                      </button>
                    )}
                    {rel.compatible === true && (
                      <button
                        onClick={() => void runFleetRollout(rel.id)}
                        disabled={fleetRolling === rel.id}
                        className="rounded-md border border-primary px-2 py-1 text-xs text-primary hover:bg-primary/10 disabled:opacity-50"
                        title="Fleet Rollout (PRD §25.5): rolling update across all enrolled nodes"
                      >
                        {fleetRolling === rel.id ? 'Rolling…' : 'Fleet Rollout'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Jobs tab ───────────────────────────────────────────────────────────────────

function JobsTab() {
  const [jobs, setJobs] = useState<UpdateJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [selectedJob, setSelectedJob] = useState<string | null>(null);
  const [canary, setCanary] = useState<CanaryEntry[]>([]);

  const load = () => {
    setLoading(true);
    updatesApi
      .listJobs()
      .then((r) => setJobs(r.jobs ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const loadCanary = (jobId: string) => {
    setSelectedJob(jobId);
    updatesApi.listCanary(jobId).then((r) => setCanary(r.entries ?? [])).catch(() => setCanary([]));
  };

  if (loading) return <p className="text-ink-secondary text-sm">Loading jobs…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load jobs" onRetry={load} />;

  return (
    <div className="space-y-4">
      {jobs.length === 0 ? (
        <EmptyState title="No update jobs">
          <span>Apply a release to create an update job.</span>
        </EmptyState>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-ink-muted">
                  <th className="pb-2 pr-4 font-medium">Job ID</th>
                  <th className="pb-2 pr-4 font-medium">State</th>
                  <th className="pb-2 pr-4 font-medium">Created</th>
                  <th className="pb-2 font-medium">Canary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {jobs.map((job) => (
                  <tr key={job.id}>
                    <td className="py-2 pr-4 font-mono text-xs">{job.id.slice(0, 8)}…</td>
                    <td className="py-2 pr-4"><StateBadge state={job.state} /></td>
                    <td className="py-2 pr-4 text-ink-secondary">{new Date(job.created_at).toLocaleString()}</td>
                    <td className="py-2">
                      <button
                        onClick={() => loadCanary(job.id)}
                        className="rounded-md border border-border px-2 py-1 text-xs hover:bg-elevated"
                      >
                        View canary
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {selectedJob && (
            <div className="mt-4 rounded-md border border-border p-4">
              <h3 className="text-sm font-medium text-ink mb-2">Canary rollout — job {selectedJob.slice(0, 8)}…</h3>
              {canary.length === 0 ? (
                <p className="text-xs text-ink-secondary">No canary entries yet.</p>
              ) : (
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border text-left text-ink-muted">
                      <th className="pb-1 pr-3 font-medium">Server</th>
                      <th className="pb-1 font-medium">State</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {canary.map((e) => (
                      <tr key={e.id}>
                        <td className="py-1 pr-3 font-mono">{e.server_id.slice(0, 8)}…</td>
                        <td className="py-1"><StateBadge state={e.state} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Modules tab ────────────────────────────────────────────────────────────────

function ModulesTab() {
  const [modules, setModules] = useState<ModuleUpdate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    updatesApi
      .listModules()
      .then((r) => setModules(r.modules ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <p className="text-ink-secondary text-sm">Loading modules…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load modules" />;

  return (
    <div>
      {modules.length === 0 ? (
        <EmptyState title="No modules tracked">
          <span>Modules will appear here once the controller registers them.</span>
        </EmptyState>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-ink-muted">
              <th className="pb-2 pr-4 font-medium">Module</th>
              <th className="pb-2 pr-4 font-medium">Current</th>
              <th className="pb-2 pr-4 font-medium">Latest</th>
              <th className="pb-2 font-medium">State</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {modules.map((m) => (
              <tr key={m.id}>
                <td className="py-2 pr-4 font-mono text-xs">{m.module_name}</td>
                <td className="py-2 pr-4 text-ink-secondary">{m.current_ver}</td>
                <td className="py-2 pr-4">{m.latest_ver ?? '—'}</td>
                <td className="py-2"><StateBadge state={m.state} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────

const TABS: { id: Tab; label: string }[] = [
  { id: 'releases', label: 'Releases' },
  { id: 'jobs', label: 'Update Jobs' },
  { id: 'modules', label: 'Modules' },
];

export function UpdatesPage() {
  const [tab, setTab] = useState<Tab>('releases');

  return (
    <div className="px-6 py-8">
      <div className="mb-6">
        <h1 className="text-xl font-semibold text-ink">Update Platform</h1>
        <p className="mt-1 text-sm text-ink-secondary">
          Discover, verify and apply JAWAKER panel and node-agent updates.
        </p>
      </div>

      <div className="mb-6 flex gap-1 border-b border-border">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              tab === t.id
                ? 'border-b-2 border-accent text-accent'
                : 'text-ink-secondary hover:text-ink'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'releases' && <ReleasesTab />}
      {tab === 'jobs' && <JobsTab />}
      {tab === 'modules' && <ModulesTab />}
    </div>
  );
}
