import { useEffect, useState } from 'react';
import { jobsApi, ApiError } from '../api/client';
import type { JobSummary } from '../api/client';
import { ErrorNote } from '../components/ui';

function statusBadge(state: string) {
  switch (state) {
    case 'running':
    case 'leased':
      return (
        <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium bg-indigo-50 text-indigo-700">
          <span className="h-1.5 w-1.5 rounded-full bg-indigo-600 animate-pulse" />
          {state}
        </span>
      );
    case 'queued':
      return (
        <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium bg-amber-50 text-amber-700">
          <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
          {state}
        </span>
      );
    case 'succeeded':
      return (
        <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium bg-emerald-50 text-emerald-700">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
          done
        </span>
      );
    case 'failed':
    case 'dead_letter':
      return (
        <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium bg-red-50 text-red-700">
          <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
          failed
        </span>
      );
    case 'canceled':
      return (
        <span className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium bg-slate-100 text-slate-600">
          cancelled
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium bg-slate-100 text-slate-600">
          {state}
        </span>
      );
  }
}

function formatDuration(createdAt: string, completedAt?: string | null): string {
  const start = new Date(createdAt).getTime();
  const end = completedAt ? new Date(completedAt).getTime() : Date.now();
  const diffSec = Math.max(0, Math.floor((end - start) / 1000));
  if (diffSec < 60) return `${diffSec}s`;
  const mins = Math.floor(diffSec / 60);
  const secs = diffSec % 60;
  return `${mins}m ${secs}s`;
}

export function WorkersPage() {
  const [jobs, setJobs] = useState<JobSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | Error | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const res = await jobsApi.list();
      setJobs(res.jobs ?? []);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 10000);
    return () => clearInterval(timer);
  }, []);

  async function handleCancel(id: string) {
    try {
      await jobsApi.cancel(id);
      void load();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  }

  const active = jobs.filter((j) => ['queued', 'leased', 'running'].includes(j.state));
  const finished = jobs.filter((j) => !['queued', 'leased', 'running'].includes(j.state));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Workers & Jobs</h1>
          <p className="text-sm text-slate-500">Background job queue and async task orchestration.</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
            Updates every 10s
          </span>
          <button
            onClick={() => void load()}
            className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 active:scale-95 transition-all"
          >
            Refresh
          </button>
        </div>
      </div>

      {error && <ErrorNote error={error} title="Failed to load jobs" onRetry={() => void load()} />}

      {/* Active Jobs Card */}
      <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        <div className="border-b border-slate-100 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold text-slate-900">Active Jobs</h2>
            <span className="inline-flex items-center rounded-full bg-indigo-50 px-2.5 py-0.5 text-xs font-medium text-indigo-700">
              {active.length}
            </span>
          </div>
        </div>

        {loading && active.length === 0 ? (
          <div className="px-6 py-12 text-center text-sm text-slate-500">Loading active jobs…</div>
        ) : active.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <div className="text-3xl mb-2">⚡</div>
            <p className="text-sm font-medium text-slate-900">No active jobs</p>
            <p className="text-xs text-slate-500">There are no tasks running or waiting in the queue.</p>
          </div>
        ) : (
          <JobTable
            jobs={active}
            onCancel={handleCancel}
            showCancel
            expandedId={expandedId}
            onToggleExpand={(id) => setExpandedId(expandedId === id ? null : id)}
          />
        )}
      </div>

      {/* Recent / Finished Jobs Card */}
      <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        <div className="border-b border-slate-100 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold text-slate-900">Recent Completed Jobs</h2>
            <span className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-600">
              {finished.length}
            </span>
          </div>
        </div>

        {finished.length === 0 ? (
          <div className="px-6 py-12 text-center text-sm text-slate-500">
            No completed jobs recorded yet.
          </div>
        ) : (
          <JobTable
            jobs={finished}
            onCancel={handleCancel}
            showCancel={false}
            expandedId={expandedId}
            onToggleExpand={(id) => setExpandedId(expandedId === id ? null : id)}
          />
        )}
      </div>
    </div>
  );
}

function JobTable({
  jobs,
  onCancel,
  showCancel,
  expandedId,
  onToggleExpand,
}: {
  jobs: JobSummary[];
  onCancel: (id: string) => void;
  showCancel: boolean;
  expandedId: string | null;
  onToggleExpand: (id: string) => void;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr>
            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Type</th>
            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Status</th>
            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Step</th>
            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Progress</th>
            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Duration</th>
            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Attempts</th>
            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Created</th>
            {showCancel && <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Actions</th>}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {jobs.map((j) => {
            const isExpanded = expandedId === j.id;
            const pct = j.progress_total ? Math.round(((j.progress_current ?? 0) / j.progress_total) * 100) : null;
            return (
              <tr key={j.id} className="group hover:bg-slate-50 transition-colors">
                <td className="px-4 py-3">
                  <div className="font-mono text-xs font-medium text-slate-900">{j.type}</div>
                  <div className="text-[10px] text-slate-400 font-mono">{j.id.slice(0, 8)}</div>
                </td>
                <td className="px-4 py-3">
                  {statusBadge(j.state)}
                </td>
                <td className="px-4 py-3">
                  {j.current_step ? (
                    <button
                      type="button"
                      onClick={() => onToggleExpand(j.id)}
                      className="inline-flex items-center gap-1 text-xs text-indigo-600 hover:text-indigo-800 font-medium cursor-pointer"
                      title="Click to view details"
                    >
                      <span className="truncate max-w-[120px]">{j.current_step}</span>
                      <svg className={`h-3 w-3 transform transition-transform ${isExpanded ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    </button>
                  ) : (
                    <span className="text-xs text-slate-400">-</span>
                  )}
                  {isExpanded && j.current_step && (
                    <div className="mt-1 p-2 rounded bg-slate-100 text-[11px] text-slate-700 font-mono break-all max-w-xs">
                      {j.current_step}
                    </div>
                  )}
                </td>
                <td className="px-4 py-3">
                  <div className="w-24 space-y-1">
                    <div className="flex justify-between text-[11px] text-slate-500 font-medium">
                      <span>{j.progress_current}</span>
                      {j.progress_total != null && <span>/ {j.progress_total}</span>}
                    </div>
                    {pct !== null && (
                      <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-indigo-600 rounded-full transition-all duration-300"
                          style={{ width: `${Math.min(100, Math.max(0, pct))}%` }}
                        />
                      </div>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3 text-xs text-slate-500 whitespace-nowrap">
                  {formatDuration(j.created_at, null)}
                </td>
                <td className="px-4 py-3 text-xs text-slate-500">
                  <span className={j.attempt_count > 1 ? 'font-medium text-amber-600' : ''}>
                    {j.attempt_count}
                  </span>
                  <span className="text-slate-400">/{j.max_attempts}</span>
                </td>
                <td className="px-4 py-3 text-xs text-slate-400 whitespace-nowrap">
                  {new Date(j.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                </td>
                {showCancel && (
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      onClick={() => onCancel(j.id)}
                      className="rounded-lg border border-red-200 bg-white px-3 py-1.5 text-xs font-medium text-red-600 hover:bg-red-50 active:scale-95 transition-all"
                    >
                      Cancel
                    </button>
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
