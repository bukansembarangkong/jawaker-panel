import { useCallback, useEffect, useState } from 'react';
import { auditLogApi, revisionApi, type AuditEventItem, type RevisionSummary } from '../api/client';
import { EmptyState, primaryButtonClass, secondaryButtonClass, StatusBadge } from '../components/ui';

export function AuditLogPage() {
  const [tab, setTab] = useState<'events' | 'revisions'>('events');
  const [events, setEvents] = useState<AuditEventItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Revision history state
  const [revisions, setRevisions] = useState<RevisionSummary[]>([]);
  const [revLoading, setRevLoading] = useState(false);
  const [revResType, setRevResType] = useState('');
  const [revState, setRevState] = useState('');

  // Filters
  const [actionFilter, setActionFilter] = useState('');
  const [resTypeFilter, setResTypeFilter] = useState('');
  const [resultFilter, setResultFilter] = useState('');
  const [offset, setOffset] = useState(0);
  const limit = 50;

  const loadRevisions = useCallback(async () => {
    setRevLoading(true);
    try {
      const data = await revisionApi.list({
        resource_type: revResType || undefined,
        state: revState || undefined,
        limit: 50,
      });
      setRevisions(data.revisions || []);
    } catch {
      setRevisions([]);
    } finally {
      setRevLoading(false);
    }
  }, [revResType, revState]);

  useEffect(() => {
    if (tab === 'revisions') void loadRevisions();
  }, [tab, loadRevisions]);

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

      {/* Tab nav */}
      <nav className="flex gap-1 border-b border-line pb-px">
        {(['events', 'revisions'] as const).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition ${
              tab === t
                ? 'border-primary text-primary'
                : 'border-transparent text-ink-secondary hover:text-ink'
            }`}
          >
            {t === 'events' ? 'Audit Events' : 'Revision History'}
          </button>
        ))}
      </nav>

      {tab === 'events' && (
        <>
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
                      <td className="px-3 py-2 text-ink-muted">{ev.source_ip || '-'}</td>
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
        </>
      )}

      {tab === 'revisions' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 rounded-lg border border-line bg-surface p-4">
            <div>
              <label className="block text-xs font-medium text-ink-muted mb-1">Resource Type</label>
              <input
                type="text"
                placeholder="e.g. site, app, database"
                value={revResType}
                onChange={(e) => setRevResType(e.target.value)}
                className="w-full rounded border border-border bg-canvas px-3 py-1.5 text-xs text-ink"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-ink-muted mb-1">State</label>
              <select
                value={revState}
                onChange={(e) => setRevState(e.target.value)}
                className="w-full rounded border border-border bg-canvas px-3 py-1.5 text-xs text-ink"
              >
                <option value="">All states</option>
                <option value="draft">Draft</option>
                <option value="validated">Validated</option>
                <option value="applied">Applied</option>
                <option value="failed">Failed</option>
                <option value="rolled_back">Rolled Back</option>
                <option value="superseded">Superseded</option>
              </select>
            </div>
          </div>

          <button type="button" onClick={() => void loadRevisions()} className={`${secondaryButtonClass} text-xs`}>
            Refresh
          </button>

          {revLoading ? (
            <p className="text-xs text-ink-muted">Loading revisions…</p>
          ) : revisions.length === 0 ? (
            <EmptyState title="No revisions found">
              <span>No revision records match your filter.</span>
            </EmptyState>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-line bg-surface">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-line bg-canvas/50 text-ink-muted">
                  <tr>
                    <th className="px-3 py-2 font-medium">ID</th>
                    <th className="px-3 py-2 font-medium">Resource</th>
                    <th className="px-3 py-2 font-medium">State</th>
                    <th className="px-3 py-2 font-medium">Git Sync</th>
                    <th className="px-3 py-2 font-medium">Hash</th>
                    <th className="px-3 py-2 font-medium">Created</th>
                    <th className="px-3 py-2 font-medium">Applied</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line font-mono">
                  {revisions.map((rev) => (
                    <tr key={rev.id} className="hover:bg-elevated/40">
                      <td className="px-3 py-2 text-ink-muted">{rev.id.slice(0, 8)}…</td>
                      <td className="px-3 py-2">
                        <span className="text-primary">{rev.resource_type}</span>
                        <span className="text-ink-muted ml-1">:{rev.resource_id.slice(0, 8)}</span>
                      </td>
                      <td className="px-3 py-2 font-sans">
                        <StatusBadge
                          state={
                            rev.state === 'applied'
                              ? 'Healthy'
                              : rev.state === 'failed' || rev.state === 'rolled_back'
                              ? 'Failed'
                              : rev.state === 'validated'
                              ? 'Running'
                              : 'Pending'
                          }
                          detail={rev.state}
                        />
                      </td>
                      <td className="px-3 py-2 text-ink-secondary">{rev.git_sync_state}</td>
                      <td className="px-3 py-2 text-ink-muted">{rev.candidate_hash.slice(0, 12)}…</td>
                      <td className="px-3 py-2 font-sans">{new Date(rev.created_at).toLocaleString()}</td>
                      <td className="px-3 py-2 font-sans text-ink-muted">
                        {rev.applied_at ? new Date(rev.applied_at).toLocaleString() : '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

