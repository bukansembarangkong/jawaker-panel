import { useCallback, useEffect, useState } from 'react';
import { auditLogApi, revisionApi, type AuditEventItem, type RevisionSummary } from '../api/client';

export function AuditLogPage() {
  const [tab, setTab] = useState<'events' | 'revisions'>('events');
  const [events, setEvents] = useState<AuditEventItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Expandable row state for events
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);

  // Revision history state
  const [revisions, setRevisions] = useState<RevisionSummary[]>([]);
  const [revLoading, setRevLoading] = useState(false);
  const [revResType, setRevResType] = useState('');
  const [revState, setRevState] = useState('');
  const [expandedRevId, setExpandedRevId] = useState<string | null>(null);

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

  const getResultBadge = (result: string) => {
    switch (result.toLowerCase()) {
      case 'success':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-medium text-emerald-700 border border-emerald-200">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
            Success
          </span>
        );
      case 'denied':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-red-50 px-2.5 py-0.5 text-xs font-medium text-red-700 border border-red-200">
            <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
            Denied
          </span>
        );
      case 'failure':
      case 'failed':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-red-50 px-2.5 py-0.5 text-xs font-medium text-red-700 border border-red-200">
            <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
            Failed
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-50 px-2.5 py-0.5 text-xs font-medium text-amber-700 border border-amber-200">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
            {result}
          </span>
        );
    }
  };

  const getRevStateBadge = (state: string) => {
    switch (state.toLowerCase()) {
      case 'applied':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-medium text-emerald-700 border border-emerald-200">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
            Applied
          </span>
        );
      case 'failed':
      case 'rolled_back':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-red-50 px-2.5 py-0.5 text-xs font-medium text-red-700 border border-red-200">
            <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
            {state === 'rolled_back' ? 'Rolled Back' : 'Failed'}
          </span>
        );
      case 'validated':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-indigo-50 px-2.5 py-0.5 text-xs font-medium text-indigo-700 border border-indigo-200">
            <span className="h-1.5 w-1.5 rounded-full bg-indigo-500" />
            Validated
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-600 border border-slate-200">
            <span className="h-1.5 w-1.5 rounded-full bg-slate-400" />
            {state}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Audit Trail & Revisions</h1>
          <p className="text-sm text-slate-500">
            Immutable, append-only security audit log recording every privileged operation across the panel.
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <a
            href={csvUrl}
            download="audit_log.csv"
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50 hover:border-slate-300 active:scale-95 transition-all"
          >
            <svg className="h-4 w-4 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Export CSV
          </a>
          <button
            type="button"
            onClick={() => void loadEvents()}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-200 gap-1 pb-px">
        {(['events', 'revisions'] as const).map((t) => {
          const active = tab === t;
          return (
            <button
              key={t}
              type="button"
              onClick={() => setTab(t)}
              className={`px-4 py-2 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
                active
                  ? 'border-indigo-600 text-indigo-600 bg-indigo-50/50 rounded-t-md'
                  : 'border-transparent text-slate-600 hover:text-slate-900 hover:border-slate-300'
              }`}
            >
              {t === 'events' ? 'Audit Events' : 'Revision History'}
            </button>
          );
        })}
      </div>

      {/* Tab: Events */}
      {tab === 'events' && (
        <div className="space-y-4">
          {/* Filters Card */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-3">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Filter Events</h2>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">Action</label>
                <input
                  type="text"
                  placeholder="e.g. site.create, app.deploy"
                  value={actionFilter}
                  onChange={(e) => {
                    setActionFilter(e.target.value);
                    setOffset(0);
                  }}
                  className="w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm text-slate-800 placeholder-slate-400 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 transition-all"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">Resource Type</label>
                <input
                  type="text"
                  placeholder="e.g. database, site, app"
                  value={resTypeFilter}
                  onChange={(e) => {
                    setResTypeFilter(e.target.value);
                    setOffset(0);
                  }}
                  className="w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm text-slate-800 placeholder-slate-400 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 transition-all"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">Result</label>
                <select
                  value={resultFilter}
                  onChange={(e) => {
                    setResultFilter(e.target.value);
                    setOffset(0);
                  }}
                  className="w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 transition-all"
                >
                  <option value="">All results</option>
                  <option value="success">Success</option>
                  <option value="failure">Failure</option>
                  <option value="denied">Denied</option>
                </select>
              </div>
            </div>
          </div>

          {error && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">
              {error}
            </div>
          )}

          {/* Table Card */}
          <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
            {loading ? (
              <div className="py-16 text-center text-sm text-slate-400">Loading audit events…</div>
            ) : events.length === 0 ? (
              <div className="py-16 text-center">
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-slate-100 text-2xl">
                  📋
                </div>
                <h3 className="mt-3 text-sm font-semibold text-slate-900">No audit events found</h3>
                <p className="mt-1 text-xs text-slate-500">No events matched your current filter criteria.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Seq</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Timestamp</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Actor</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Action</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Resource</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Result</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Source IP</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50 w-10"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {events.map((ev) => {
                      const isExpanded = expandedEventId === ev.id;
                      return (
                        <tr key={ev.id} className="group hover:bg-slate-50/75 transition-colors">
                          <td colSpan={8} className="p-0">
                            <div
                              onClick={() => setExpandedEventId(isExpanded ? null : ev.id)}
                              className="flex items-center cursor-pointer select-none px-4 py-3 text-sm text-slate-800"
                            >
                              <div className="w-[6%] font-mono text-xs text-slate-400">#{ev.seq}</div>
                              <div className="w-[18%] text-xs text-slate-600">
                                {new Date(ev.occurred_at).toLocaleString()}
                              </div>
                              <div className="w-[16%]">
                                <span className="font-medium text-slate-800">{ev.actor_type}</span>
                                {ev.actor_id && (
                                  <span className="ml-1 text-[11px] font-mono text-slate-400">
                                    ({ev.actor_id.slice(0, 8)}…)
                                  </span>
                                )}
                              </div>
                              <div className="w-[20%] font-mono text-xs font-semibold text-indigo-600">
                                {ev.action}
                              </div>
                              <div className="w-[18%] font-mono text-xs text-slate-600">
                                {ev.resource_type}
                                {ev.resource_id && (
                                  <span className="text-slate-400">:{ev.resource_id.slice(0, 8)}</span>
                                )}
                              </div>
                              <div className="w-[12%]">
                                {getResultBadge(ev.result)}
                              </div>
                              <div className="w-[10%] font-mono text-xs text-slate-500">
                                {ev.source_ip || '-'}
                              </div>
                              <div className="w-6 text-right">
                                <svg
                                  className={`h-4 w-4 text-slate-400 transform transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                                  fill="none"
                                  viewBox="0 0 24 24"
                                  stroke="currentColor"
                                >
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                </svg>
                              </div>
                            </div>
                            {/* Expanded Detail Row */}
                            {isExpanded && (
                              <div className="bg-slate-50/70 border-t border-slate-100 px-6 py-4 space-y-3">
                                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
                                  <div>
                                    <span className="font-semibold text-slate-500 block">Event UUID</span>
                                    <span className="font-mono text-slate-800 break-all">{ev.id}</span>
                                  </div>
                                  <div>
                                    <span className="font-semibold text-slate-500 block">Sequence Number</span>
                                    <span className="font-mono text-slate-800">#{ev.seq}</span>
                                  </div>
                                  <div>
                                    <span className="font-semibold text-slate-500 block">Actor</span>
                                    <span className="font-mono text-slate-800 break-all">
                                      {ev.actor_type} {ev.actor_id ? `(${ev.actor_id})` : ''}
                                    </span>
                                  </div>
                                  <div>
                                    <span className="font-semibold text-slate-500 block">Target Resource</span>
                                    <span className="font-mono text-slate-800 break-all">
                                      {ev.resource_type} {ev.resource_id ? `(${ev.resource_id})` : ''}
                                    </span>
                                  </div>
                                </div>
                                <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs pt-1 border-t border-slate-200/50">
                                  <div>
                                    <span className="font-semibold text-slate-500 block">Source IP</span>
                                    <span className="font-mono text-slate-800">{ev.source_ip || 'None recorded'}</span>
                                  </div>
                                  <div>
                                    <span className="font-semibold text-slate-500 block">Timestamp</span>
                                    <span className="font-mono text-slate-800">{new Date(ev.occurred_at).toISOString()}</span>
                                  </div>
                                  <div>
                                    <span className="font-semibold text-slate-500 block">Result</span>
                                    <span className="font-mono text-slate-800 uppercase font-semibold">{ev.result}</span>
                                  </div>
                                </div>
                              </div>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {/* Pagination */}
            <div className="flex items-center justify-between border-t border-slate-100 bg-slate-50/50 px-6 py-3 text-xs text-slate-500">
              <div>Showing {events.length} records (offset {offset})</div>
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                  className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 shadow-sm hover:bg-slate-50 transition-all disabled:opacity-40"
                >
                  Previous
                </button>
                <button
                  type="button"
                  disabled={events.length < limit}
                  onClick={() => setOffset(offset + limit)}
                  className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 shadow-sm hover:bg-slate-50 transition-all disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab: Revisions */}
      {tab === 'revisions' && (
        <div className="space-y-4">
          {/* Filters Card */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-3">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Filter Revisions</h2>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">Resource Type</label>
                <input
                  type="text"
                  placeholder="e.g. site, app, database"
                  value={revResType}
                  onChange={(e) => setRevResType(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm text-slate-800 placeholder-slate-400 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 transition-all"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">State</label>
                <select
                  value={revState}
                  onChange={(e) => setRevState(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 transition-all"
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
          </div>

          {/* Table Card */}
          <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
            {revLoading ? (
              <div className="py-16 text-center text-sm text-slate-400">Loading revisions…</div>
            ) : revisions.length === 0 ? (
              <div className="py-16 text-center">
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-slate-100 text-2xl">
                  🔄
                </div>
                <h3 className="mt-3 text-sm font-semibold text-slate-900">No revisions found</h3>
                <p className="mt-1 text-xs text-slate-500">No revision records match your filter.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">ID</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Resource</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">State</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Git Sync</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Hash</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Created</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Applied</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50 w-10"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {revisions.map((rev) => {
                      const isExpanded = expandedRevId === rev.id;
                      return (
                        <tr key={rev.id} className="group hover:bg-slate-50/75 transition-colors">
                          <td colSpan={8} className="p-0">
                            <div
                              onClick={() => setExpandedRevId(isExpanded ? null : rev.id)}
                              className="flex items-center cursor-pointer select-none px-4 py-3 text-sm text-slate-800"
                            >
                              <div className="w-[12%] font-mono text-xs text-slate-500">{rev.id.slice(0, 8)}…</div>
                              <div className="w-[18%]">
                                <span className="font-semibold text-indigo-600">{rev.resource_type}</span>
                                <span className="font-mono text-xs text-slate-400 ml-1">:{rev.resource_id.slice(0, 8)}</span>
                              </div>
                              <div className="w-[14%]">
                                {getRevStateBadge(rev.state)}
                              </div>
                              <div className="w-[14%] text-xs font-medium text-slate-600">{rev.git_sync_state}</div>
                              <div className="w-[14%] font-mono text-xs text-slate-500">{rev.candidate_hash.slice(0, 10)}…</div>
                              <div className="w-[14%] text-xs text-slate-500">{new Date(rev.created_at).toLocaleDateString()}</div>
                              <div className="w-[14%] text-xs text-slate-500">
                                {rev.applied_at ? new Date(rev.applied_at).toLocaleDateString() : '-'}
                              </div>
                              <div className="w-6 text-right">
                                <svg
                                  className={`h-4 w-4 text-slate-400 transform transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                                  fill="none"
                                  viewBox="0 0 24 24"
                                  stroke="currentColor"
                                >
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                </svg>
                              </div>
                            </div>
                            {isExpanded && (
                              <div className="bg-slate-50/70 border-t border-slate-100 px-6 py-4 space-y-2">
                                <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs">
                                  <div>
                                    <span className="font-semibold text-slate-500 block">Full ID</span>
                                    <span className="font-mono text-slate-800 break-all">{rev.id}</span>
                                  </div>
                                  <div>
                                    <span className="font-semibold text-slate-500 block">Candidate Hash</span>
                                    <span className="font-mono text-slate-800 break-all">{rev.candidate_hash}</span>
                                  </div>
                                  <div>
                                    <span className="font-semibold text-slate-500 block">Git Sync State</span>
                                    <span className="font-medium text-slate-800">{rev.git_sync_state}</span>
                                  </div>
                                </div>
                              </div>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
