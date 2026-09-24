import { useCallback, useEffect, useState } from 'react';
import { auditLogApi, type AuditEventItem } from '../api/client';
import { EmptyState, primaryButtonClass, secondaryButtonClass, StatusBadge } from '../components/ui';

export function AuditLogPage() {
  const [events, setEvents] = useState<AuditEventItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [actionFilter, setActionFilter] = useState('');
  const [resTypeFilter, setResTypeFilter] = useState('');
  const [resultFilter, setResultFilter] = useState('');
  const [offset, setOffset] = useState(0);
  const limit = 50;

  const loadEvents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await auditLogApi.list({
        action: actionFilter || undefined,
        resource_type: resTypeFilter || undefined,
        result: resultFilter || undefined,
        limit,
        offset,
      });
      setEvents(data.events || []);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load audit events');
    } finally {
      setLoading(false);
    }
  }, [actionFilter, resTypeFilter, resultFilter, offset]);

  useEffect(() => {
    void loadEvents();
  }, [loadEvents]);

  const csvUrl = auditLogApi.csvExportUrl({
    action: actionFilter || undefined,
    resource_type: resTypeFilter || undefined,
    result: resultFilter || undefined,
  });

  return (
    <div className="space-y-6 px-6 py-8">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Audit Trail & Revisions (PRD §36)</h1>
          <p className="text-sm text-ink-secondary">
            Immutable, append-only security audit log recording every privileged operation across the panel.
          </p>
        </div>
        <div className="flex gap-2">
          <a
            href={csvUrl}
            download="audit_log.csv"
            className={`${secondaryButtonClass} text-xs`}
          >
            Export CSV
          </a>
          <button
            type="button"
            onClick={() => void loadEvents()}
            className={`${primaryButtonClass} text-xs`}
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 rounded-lg border border-line bg-surface p-4">
        <div>
          <label className="block text-xs font-medium text-ink-muted mb-1">Filter by Action</label>
          <input
            type="text"
            placeholder="e.g. site.create, app.deploy"
            value={actionFilter}
            onChange={(e) => {
              setActionFilter(e.target.value);
              setOffset(0);
            }}
            className="w-full rounded border border-border bg-canvas px-3 py-1.5 text-xs text-ink"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-ink-muted mb-1">Resource Type</label>
          <input
            type="text"
            placeholder="e.g. database, site, app"
            value={resTypeFilter}
            onChange={(e) => {
              setResTypeFilter(e.target.value);
              setOffset(0);
            }}
            className="w-full rounded border border-border bg-canvas px-3 py-1.5 text-xs text-ink"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-ink-muted mb-1">Result</label>
          <select
            value={resultFilter}
            onChange={(e) => {
              setResultFilter(e.target.value);
              setOffset(0);
            }}
            className="w-full rounded border border-border bg-canvas px-3 py-1.5 text-xs text-ink"
          >
            <option value="">All results</option>
            <option value="success">Success</option>
            <option value="failure">Failure</option>
            <option value="denied">Denied</option>
          </select>
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-rose-500/20 bg-rose-500/10 p-3 text-xs text-rose-500">
          {error}
        </div>
      )}

      {loading ? (
        <p className="text-xs text-ink-muted">Loading audit events…</p>
      ) : events.length === 0 ? (
        <EmptyState title="No audit events found">
          <span>No matching events found in the audit trail.</span>
        </EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-line bg-surface">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-line bg-canvas/50 text-ink-muted">
              <tr>
                <th className="px-3 py-2 font-medium">Seq</th>
                <th className="px-3 py-2 font-medium">Timestamp</th>
                <th className="px-3 py-2 font-medium">Actor</th>
                <th className="px-3 py-2 font-medium">Action</th>
                <th className="px-3 py-2 font-medium">Resource</th>
                <th className="px-3 py-2 font-medium">Result</th>
                <th className="px-3 py-2 font-medium">Source IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line font-mono">
              {events.map((ev) => (
                <tr key={ev.id} className="hover:bg-elevated/40">
                  <td className="px-3 py-2 text-ink-muted">#{ev.seq}</td>
                  <td className="px-3 py-2 text-ink-secondary font-sans">
                    {new Date(ev.occurred_at).toLocaleString()}
                  </td>
                  <td className="px-3 py-2">
                    <span className="text-ink">{ev.actor_type}</span>
                    {ev.actor_id && (
                      <span className="text-ink-muted text-[10px] ml-1">
                        ({ev.actor_id.slice(0, 8)}…)
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 font-semibold text-primary">{ev.action}</td>
                  <td className="px-3 py-2 text-ink-muted">
                    {ev.resource_type}
                    {ev.resource_id && <span>:{ev.resource_id.slice(0, 8)}</span>}
                  </td>
                  <td className="px-3 py-2 font-sans">
                    <StatusBadge
                      state={
                        ev.result === 'success'
                          ? 'Healthy'
                          : ev.result === 'denied'
                          ? 'Failed'
                          : 'Warning'
                      }
                      detail={ev.result}
                    />
                  </td>
                  <td className="px-3 py-2 text-ink-muted">{ev.source_ip || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      <div className="flex items-center justify-between text-xs text-ink-muted">
        <div>Showing {events.length} records (offset {offset})</div>
        <div className="flex gap-2">
          <button
            type="button"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - limit))}
            className={`${secondaryButtonClass} text-xs disabled:opacity-40`}
          >
            Previous
          </button>
          <button
            type="button"
            disabled={events.length < limit}
            onClick={() => setOffset(offset + limit)}
            className={`${secondaryButtonClass} text-xs disabled:opacity-40`}
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
