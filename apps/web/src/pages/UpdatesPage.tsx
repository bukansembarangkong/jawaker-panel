import { useEffect, useState } from 'react';
import { goeyToast } from 'goey-toast';
import { type OperationalState, ErrorNote, StatusBadge } from '../components/ui';
import { type CanaryEntry, type ModuleUpdate, type UpdateJob, type UpdateRelease, updatesApi } from '../api/client';

type Tab = 'releases' | 'jobs' | 'modules';

function stateToOperational(state: string): OperationalState {
  const map: Record<string, OperationalState> = {
    done: 'Healthy', ready: 'Healthy', pass: 'Healthy', pending: 'Pending', idle: 'Disabled',
    preflight: 'Running', downloading: 'Running', verifying: 'Running', applying: 'Running',
    updating: 'Updating', running: 'Running', failed: 'Failed', rolled_back: 'Warning', paused: 'Paused',
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

// ?? Releases tab ???????????????????????????????????????????????????????????????

function ReleasesTab() {
  const [releases, setReleases] = useState<UpdateRelease[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [channel, setChannel] = useState('');
  const [applying, setApplying] = useState<string | null>(null);
  const [fleetRolling, setFleetRolling] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    updatesApi.listReleases(channel || undefined)
      .then((r) => setReleases(r.releases ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [channel]); // eslint-disable-line react-hooks/exhaustive-deps

  const runPreflight = async (id: string) => {
    try { await updatesApi.runPreflight(id); load(); }
    catch (e) { setError(e instanceof Error ? e : new Error(String(e))); }
  };

  const applyRelease = async (id: string) => {
    setApplying(id);
    try { await updatesApi.applyUpdate(id); load(); }
    catch (e) { setError(e instanceof Error ? e : new Error(String(e))); }
    finally { setApplying(null); }
  };

  const runFleetRollout = async (id: string) => {
    setFleetRolling(id);
    try {
      const res = await updatesApi.fleetRollout(id);
      goeyToast.success(`Fleet rollout started: job ${res.job_id.slice(0, 8)}? across ${res.total_nodes} nodes (batch ${res.batch_size}).`);
    } catch (e) { setError(e instanceof Error ? e : new Error(String(e))); }
    finally { setFleetRolling(null); }
  };

  if (loading) return <p className="text-slate-500 text-sm">Loading releases?</p>;
  if (error) return <ErrorNote error={error} title="Failed to load releases" onRetry={load} />;

  if (releases.length === 0) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
        <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100"><svg className="h-6 w-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" /></svg></div>
        <h3 className="text-base font-semibold text-slate-900">Up to date</h3>
        <p className="text-sm text-slate-500 mt-1">No releases discovered. Run release discovery to check for updates.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <select
          value={channel}
          onChange={(e) => setChannel(e.target.value)}
          className="block rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
        >
          <option value="">All channels</option>
          <option value="stable">stable</option>
          <option value="beta">beta</option>
          <option value="edge">edge</option>
        </select>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        {releases.map((rel) => (
          <div key={rel.id} className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <span className="rounded-full px-2.5 py-0.5 text-xs font-mono font-medium bg-indigo-50 text-indigo-700 border border-indigo-200">
                  v{rel.version}
                </span>
                <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                  rel.channel === 'stable' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                  rel.channel === 'beta' ? 'bg-amber-50 text-amber-700 border border-amber-200' :
                  'bg-purple-50 text-purple-700 border border-purple-200'
                }`}>{rel.channel}</span>
              </div>
              <p className="text-sm text-slate-500">Released: {new Date(rel.published_at).toLocaleDateString()}</p>
              {rel.notes && <p className="mt-2 text-xs text-slate-600 line-clamp-3">{rel.notes}</p>}
            </div>
            <div className="flex items-center justify-between pt-2 border-t border-slate-100">
              <CompatBadge compatible={rel.compatible} />
              <div className="flex items-center gap-2">
                {rel.compatible === null && (
                  <button onClick={() => void runPreflight(rel.id)} className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-all">Preflight</button>
                )}
                {rel.compatible === true && (
                  <>
                    <button onClick={() => void applyRelease(rel.id)} disabled={applying === rel.id} className="rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-700 active:scale-95 transition-all disabled:opacity-50">
                      {applying === rel.id ? 'Applying?' : 'Install'}
                    </button>
                    <button onClick={() => void runFleetRollout(rel.id)} disabled={fleetRolling === rel.id} className="rounded-lg border border-indigo-300 bg-indigo-50 px-3 py-1.5 text-xs font-medium text-indigo-700 hover:bg-indigo-100 transition-all disabled:opacity-50" title="Fleet Rollout">
                      {fleetRolling === rel.id ? 'Rolling?' : 'Fleet Rollout'}
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ?? Jobs tab ???????????????????????????????????????????????????????????????????

function JobsTab() {
  const [jobs, setJobs] = useState<UpdateJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [selectedJob, setSelectedJob] = useState<string | null>(null);
  const [canary, setCanary] = useState<CanaryEntry[]>([]);

  const load = () => {
    setLoading(true);
    updatesApi.listJobs()
      .then((r) => setJobs(r.jobs ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const loadCanary = (jobId: string) => {
    setSelectedJob(jobId);
    updatesApi.listCanary(jobId).then((r) => setCanary(r.entries ?? [])).catch(() => setCanary([]));
  };

  if (loading) return <p className="text-slate-500 text-sm">Loading jobs?</p>;
  if (error) return <ErrorNote error={error} title="Failed to load jobs" onRetry={load} />;

  return (
    <div className="space-y-4">
      {jobs.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
          <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100"><svg className="h-6 w-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" /></svg></div>
          <h3 className="text-base font-semibold text-slate-900">No update jobs</h3>
          <p className="text-sm text-slate-500 mt-1">Apply a release to create an update job.</p>
        </div>
      ) : (
        <>
          <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-slate-200">
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Job ID</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">State</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Progress</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Created</th>
                    <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Canary</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {jobs.map((job) => {
                    const isRunning = ['preflight', 'downloading', 'verifying', 'applying', 'updating', 'running'].includes(job.state);
                    return (
                      <tr key={job.id} className="hover:bg-slate-50/50 transition-colors">
                        <td className="px-4 py-3 text-sm font-mono text-slate-800">{job.id.slice(0, 8)}?</td>
                        <td className="px-4 py-3 text-sm"><StateBadge state={job.state} /></td>
                        <td className="px-4 py-3 text-sm w-32">
                          <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
                            <div
                              className={`h-1.5 rounded-full ${isRunning ? 'bg-indigo-500 animate-pulse' : job.state === 'done' ? 'bg-emerald-500' : 'bg-slate-200'}`}
                              style={{ width: isRunning ? '60%' : job.state === 'done' ? '100%' : '0%' }}
                            />
                          </div>
                        </td>
                        <td className="px-4 py-3 text-sm text-slate-500">{new Date(job.created_at).toLocaleString()}</td>
                        <td className="px-4 py-3 text-sm text-right">
                          <button
                            onClick={() => loadCanary(job.id)}
                            className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-all ${selectedJob === job.id ? 'bg-indigo-50 border-indigo-300 text-indigo-700' : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'}`}
                          >
                            View canary
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
          {selectedJob && (
            <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold text-slate-900">Canary rollout ? job {selectedJob.slice(0, 8)}?</h3>
                <button type="button" onClick={() => setSelectedJob(null)} className="text-xs text-slate-500 hover:text-slate-700">Close</button>
              </div>
              {canary.length === 0 ? (
                <p className="text-sm text-slate-500">No canary entries yet.</p>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-200">
                      <th className="pb-2 pr-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">Server</th>
                      <th className="pb-2 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">State</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {canary.map((e) => (
                      <tr key={e.id}>
                        <td className="py-2 pr-4 font-mono text-xs text-slate-800">{e.server_id.slice(0, 8)}?</td>
                        <td className="py-2"><StateBadge state={e.state} /></td>
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

// ?? Modules tab ????????????????????????????????????????????????????????????????

function ModulesTab() {
  const [modules, setModules] = useState<ModuleUpdate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    updatesApi.listModules()
      .then((r) => setModules(r.modules ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <p className="text-slate-500 text-sm">Loading modules?</p>;
  if (error) return <ErrorNote error={error} title="Failed to load modules" />;

  return (
    <div>
      {modules.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
          <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100"><svg className="h-6 w-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" /></svg></div>
          <h3 className="text-base font-semibold text-slate-900">No modules tracked</h3>
          <p className="text-sm text-slate-500 mt-1">Modules will appear here once the controller registers them.</p>
        </div>
      ) : (
        <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-slate-200">
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Module</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Current</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Latest</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">State</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {modules.map((m) => (
                  <tr key={m.id} className="hover:bg-slate-50/50 transition-colors">
                    <td className="px-4 py-3 text-sm font-mono text-slate-900">{m.module_name}</td>
                    <td className="px-4 py-3 text-sm text-slate-500">{m.current_ver}</td>
                    <td className="px-4 py-3 text-sm text-slate-800">{m.latest_ver ?? '-'}</td>
                    <td className="px-4 py-3 text-sm"><StateBadge state={m.state} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ?? Main page ??????????????????????????????????????????????????????????????????

const TABS: { id: Tab; label: string }[] = [
  { id: 'releases', label: 'Releases' },
  { id: 'jobs', label: 'Update Jobs' },
  { id: 'modules', label: 'Modules' },
];

export function UpdatesPage() {
  const [tab, setTab] = useState<Tab>('releases');

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Update Platform</h1>
          <p className="text-sm text-slate-500">Discover, verify and apply JAWAKER panel and node-agent updates.</p>
        </div>
      </div>
      <div className="flex gap-4 border-b border-slate-200">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`pb-2 text-sm font-medium border-b-2 transition-all ${tab === t.id ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500 hover:text-slate-800'}`}
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
