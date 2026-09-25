import { useEffect, useState } from 'react';
import { jobsApi, ApiError } from '../api/client';
import type { JobSummary } from '../api/client';
import { ErrorNote, EmptyState, secondaryButtonClass } from '../components/ui';

function stateColor(state: string): string {
  switch (state) {
    case 'running': case 'leased': return 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400';
    case 'queued': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400';
    case 'succeeded': return 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400';
    case 'failed': case 'dead_letter': return 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400';
    case 'canceled': return 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400';
    default: return 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400';
  }
}

export function WorkersPage() {
  const [jobs, setJobs] = useState<JobSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | Error | null>(null);

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
    <div className="p-6 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Workers & Jobs</h1>
          <p className="text-sm text-ink-secondary mt-1">Background job queue - refreshes every 10s.</p>
        </div>
        <button onClick={() => void load()} className={secondaryButtonClass}>Refresh</button>
      </div>

      {error && <ErrorNote error={error} title="Failed to load jobs" onRetry={() => void load()} />}

      <section>
        <h2 className="text-base font-medium text-ink mb-3">Active ({active.length})</h2>
        {loading && active.length === 0 ? (
          <p className="text-sm text-ink-secondary">Loading…</p>
        ) : active.length === 0 ? (
          <EmptyState title="No active jobs">No jobs currently running or queued.</EmptyState>
        ) : (
          <JobTable jobs={active} onCancel={handleCancel} showCancel />
        )}
      </section>

      <section>
        <h2 className="text-base font-medium text-ink mb-3">Recent ({finished.length})</h2>
        {finished.length === 0 ? (
          <p className="text-sm text-ink-secondary">No finished jobs yet.</p>
        ) : (
          <JobTable jobs={finished} onCancel={handleCancel} showCancel={false} />
        )}
      </section>
    </div>
  );
}

function JobTable({
  jobs,
  onCancel,
  showCancel,
}: {
  jobs: JobSummary[];
  onCancel: (id: string) => void;
  showCancel: boolean;
}) {
  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-sm">
        <thead className="bg-elevated text-ink-secondary">
          <tr>
            <th className="px-4 py-2 text-left font-medium">Type</th>
            <th className="px-4 py-2 text-left font-medium">State</th>
            <th className="px-4 py-2 text-left font-medium">Step</th>
            <th className="px-4 py-2 text-left font-medium">Progress</th>
            <th className="px-4 py-2 text-left font-medium">Attempts</th>
            <th className="px-4 py-2 text-left font-medium">Created</th>
            {showCancel && <th className="px-4 py-2 text-left font-medium">Actions</th>}
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {jobs.map((j) => (
            <tr key={j.id} className="bg-surface hover:bg-elevated/50">
              <td className="px-4 py-2 font-mono text-xs text-ink">{j.type}</td>
              <td className="px-4 py-2">
                <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${stateColor(j.state)}`}>{j.state}</span>
              </td>
              <td className="px-4 py-2 text-ink-secondary text-xs">{j.current_step ?? '-'}</td>
              <td className="px-4 py-2 text-ink-secondary text-xs">
                {j.progress_total != null ? `${j.progress_current}/${j.progress_total}` : `${j.progress_current}`}
              </td>
              <td className="px-4 py-2 text-ink-secondary text-xs">{j.attempt_count}/{j.max_attempts}</td>
              <td className="px-4 py-2 text-ink-secondary text-xs">{new Date(j.created_at).toLocaleString()}</td>
              {showCancel && (
                <td className="px-4 py-2">
                  <button onClick={() => onCancel(j.id)} className={secondaryButtonClass}>Cancel</button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
