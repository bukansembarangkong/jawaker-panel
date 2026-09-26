import { useEffect, useState } from 'react';
import { type OperationalState, ErrorNote, StatusBadge } from '../components/ui';
import { type HealthCheck, type UpgradeRecord, type RunbookEvent, hardeningApi } from '../api/client';

type Tab = 'health' | 'upgrades' | 'runbooks';

function healthState(status: string): OperationalState {
  const map: Record<string, OperationalState> = {
    ok: 'Healthy',
    degraded: 'Warning',
    failed: 'Failed',
  };
  return map[status] ?? 'Unknown';
}

function outcomeBadge(outcome: string): OperationalState {
  const map: Record<string, OperationalState> = {
    pass: 'Healthy',
    fail: 'Failed',
    partial: 'Warning',
  };
  return map[outcome] ?? 'Unknown';
}

// ── Health tab ─────────────────────────────────────────────────────────────────

function HealthTab() {
  const [checks, setChecks] = useState<HealthCheck[]>([]);
  const [overall, setOverall] = useState('');
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const load = () => {
    setLoading(true);
    hardeningApi
      .listChecks()
      .then((r) => { setChecks(r.checks ?? []); setOverall(r.overall ?? 'unknown'); })
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const runCheck = async () => {
    setRunning(true);
    try {
      const r = await hardeningApi.runChecks();
      setChecks(r.results ?? []);
      setOverall(r.overall ?? 'unknown');
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setRunning(false);
    }
  };

  if (loading) return <p className="text-sm text-slate-500">Loading health checks…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load health checks" onRetry={load} />;

  const overallHealthy = overall === 'ok';
  const overallWarn = overall === 'degraded';

  const statusIndicator = (status: string) => {
    if (status === 'ok') return { icon: '✅', color: 'text-emerald-600', bg: 'bg-emerald-50 border border-emerald-200', label: 'PASS' };
    if (status === 'degraded') return { icon: '⚠️', color: 'text-amber-600', bg: 'bg-amber-50 border border-amber-200', label: 'WARN' };
    return { icon: '❌', color: 'text-red-600', bg: 'bg-red-50 border border-red-200', label: 'FAIL' };
  };

  return (
    <div className="space-y-5">
      {/* Overall status card */}
      <div className={`flex items-center justify-between rounded-xl border p-4 ${
        overallHealthy
          ? 'bg-emerald-50 border-emerald-200'
          : overallWarn
          ? 'bg-amber-50 border-amber-200'
          : 'bg-red-50 border-red-200'
      }`}>
        <div className="flex items-center gap-3">
          <span className="text-2xl">{overallHealthy ? '🟢' : overallWarn ? '🟡' : '🔴'}</span>
          <div>
            <p className={`text-sm font-semibold ${overallHealthy ? 'text-emerald-800' : overallWarn ? 'text-amber-800' : 'text-red-800'}`}>
              System health: {overall.toUpperCase()}
            </p>
            <p className="text-xs text-slate-600">{checks.length} checks evaluated</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge state={healthState(overall)} detail={overall} />
          <button
            type="button"
            onClick={() => void runCheck()}
            disabled={running}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all disabled:opacity-50"
          >
            {running ? 'Running…' : 'Run Checks'}
          </button>
        </div>
      </div>

      {checks.length === 0 ? (
        <div className="py-12 text-center">
          <span className="text-4xl mb-2 block">🏥</span>
          <h3 className="text-sm font-semibold text-slate-900">No health checks recorded</h3>
          <p className="text-xs text-slate-500 mt-1">Click "Run Checks" to evaluate system health state.</p>
        </div>
      ) : (
        <ul className="divide-y divide-slate-100 rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
          {checks.map((c) => {
            const { icon, bg, label } = statusIndicator(c.status);
            return (
              <li key={c.id} className="flex items-center justify-between gap-4 px-5 py-4 hover:bg-slate-50/50 transition-colors">
                <div className="flex items-start gap-3">
                  <span className="text-lg leading-none mt-0.5">{icon}</span>
                  <div>
                    <p className="text-sm font-semibold text-slate-900 font-mono">{c.check_name}</p>
                    <p className="text-xs text-slate-500 mt-0.5">{c.message}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className="text-xs text-slate-400 font-mono">{c.duration_ms}ms</span>
                  <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${bg}`}>
                    {label}
                  </span>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

// ── Upgrades tab ───────────────────────────────────────────────────────────────

function UpgradesTab() {
  const [upgrades, setUpgrades] = useState<UpgradeRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    hardeningApi
      .listUpgrades()
      .then((r) => setUpgrades(r.upgrades ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <p className="text-sm text-slate-500">Loading upgrade history…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load upgrade history" onRetry={() => setError(null)} />;

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-slate-900">Upgrade History</h2>
            <p className="text-xs text-slate-500 mt-0.5">{upgrades.length} migration{upgrades.length !== 1 ? 's' : ''} on record</p>
          </div>
        </div>

        {upgrades.length === 0 ? (
          <div className="py-12 text-center">
            <span className="text-4xl mb-2 block">📜</span>
            <h3 className="text-sm font-semibold text-slate-900">No upgrades recorded</h3>
            <p className="text-xs text-slate-500 mt-1">Migration runs will appear here after deployment.</p>
          </div>
        ) : (
          <div className="relative pl-5">
            {/* timeline spine */}
            <div className="absolute left-5 top-0 bottom-0 w-px bg-slate-200 ml-2.5" />
            <ul className="space-y-0">
              {upgrades.map((u, idx) => {
                const ok = u.status === 'ok';
                return (
                  <li key={u.id} className={`flex gap-4 py-4 pr-5 ${idx < upgrades.length - 1 ? 'border-b border-slate-100' : ''}`}>
                    {/* dot */}
                    <div className={`relative z-10 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border-2 mt-0.5 ${
                      ok ? 'border-emerald-500 bg-white' : 'border-red-500 bg-white'
                    }`}>
                      <span className={`h-2 w-2 rounded-full ${ok ? 'bg-emerald-500' : 'bg-red-500'}`} />
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-1">
                        <p className="font-mono text-sm font-semibold text-slate-800 truncate">{u.migration_name}</p>
                        <div className="flex items-center gap-2 shrink-0">
                          <span className="text-xs text-slate-400 font-mono">{u.duration_ms}ms</span>
                          <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                            ok ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' : 'bg-red-50 text-red-700 border border-red-200'
                          }`}>
                            {u.status}
                          </span>
                        </div>
                      </div>
                      <p className="text-xs text-slate-500 mt-0.5 font-mono">
                        {u.applied_at.slice(0, 19).replace('T', ' ')}
                      </p>
                    </div>
                  </li>
                );
              })}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Runbooks tab ───────────────────────────────────────────────────────────────

function RunbooksTab() {
  const [events, setEvents] = useState<RunbookEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [recording, setRecording] = useState(false);
  const [form, setForm] = useState({ runbook_name: '', event_type: 'drill', outcome: 'pass', notes: '', duration_min: 0 });
  const [saving, setSaving] = useState(false);

  const load = () => {
    setLoading(true);
    hardeningApi
      .listRunbooks()
      .then((r) => setEvents(r.events ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const record = async () => {
    if (!form.runbook_name.trim()) return;
    setSaving(true);
    try {
      await hardeningApi.recordRunbook(form.runbook_name.trim(), form.event_type, form.outcome, form.notes, form.duration_min);
      setRecording(false);
      setForm({ runbook_name: '', event_type: 'drill', outcome: 'pass', notes: '', duration_min: 0 });
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <p className="text-sm text-slate-500">Loading runbook events…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load runbook events" onRetry={load} />;

  const outcomeConfig = (outcome: string) => {
    if (outcome === 'pass') return { bg: 'bg-emerald-50 text-emerald-700 border border-emerald-200', icon: '✅' };
    if (outcome === 'partial') return { bg: 'bg-amber-50 text-amber-700 border border-amber-200', icon: '⚠️' };
    return { bg: 'bg-red-50 text-red-700 border border-red-200', icon: '❌' };
  };

  const inputCls = 'w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100';

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <p className="text-xs text-slate-500">{events.length} event{events.length !== 1 ? 's' : ''} logged</p>
        <button
          type="button"
          onClick={() => setRecording(true)}
          className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
        >
          + Record Event
        </button>
      </div>

      {recording && (
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
          <div>
            <h3 className="text-base font-semibold text-slate-900">Record Runbook Event</h3>
            <p className="text-xs text-slate-500">Log a drill, incident, or test outcome against a named runbook.</p>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">Runbook Name</label>
              <input
                type="text"
                value={form.runbook_name}
                onChange={(e) => setForm((f) => ({ ...f, runbook_name: e.target.value }))}
                placeholder="e.g. db-restore-drill"
                className={inputCls}
              />
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">Event Type</label>
              <select
                value={form.event_type}
                onChange={(e) => setForm((f) => ({ ...f, event_type: e.target.value }))}
                className={inputCls}
              >
                <option value="drill">Drill</option>
                <option value="incident">Incident</option>
                <option value="recovery">Recovery</option>
                <option value="test">Test</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">Outcome</label>
              <select
                value={form.outcome}
                onChange={(e) => setForm((f) => ({ ...f, outcome: e.target.value }))}
                className={inputCls}
              >
                <option value="pass">Pass</option>
                <option value="fail">Fail</option>
                <option value="partial">Partial</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">Duration (minutes)</label>
              <input
                type="number"
                value={form.duration_min}
                onChange={(e) => setForm((f) => ({ ...f, duration_min: Number(e.target.value) }))}
                className={inputCls}
                min={0}
              />
            </div>
            <div className="sm:col-span-2">
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">Notes</label>
              <textarea
                value={form.notes}
                onChange={(e) => setForm((f) => ({ ...f, notes: e.target.value }))}
                rows={2}
                placeholder="Optional notes or observations…"
                className={inputCls}
              />
            </div>
          </div>

          <div className="flex gap-2 justify-end pt-2 border-t border-slate-100">
            <button
              type="button"
              onClick={() => setRecording(false)}
              className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => void record()}
              disabled={saving}
              className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all disabled:opacity-50"
            >
              {saving ? 'Saving…' : 'Save Event'}
            </button>
          </div>
        </div>
      )}

      {events.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
          <span className="text-4xl mb-2 block">📋</span>
          <h3 className="text-base font-semibold text-slate-900">No runbook events logged</h3>
          <p className="text-sm text-slate-500 mt-1 max-w-sm mx-auto">Record drill and incident outcomes for runbook validation and compliance audits.</p>
        </div>
      ) : (
        <ul className="divide-y divide-slate-100 rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
          {events.map((ev) => {
            const { bg: outcomeBg, icon } = outcomeConfig(ev.outcome);
            return (
              <li key={ev.id} className="flex items-start justify-between gap-4 px-5 py-4 hover:bg-slate-50/50 transition-colors">
                <div className="flex items-start gap-3">
                  <span className="text-lg leading-none mt-0.5">{icon}</span>
                  <div>
                    <p className="text-sm font-semibold text-slate-900 font-mono">{ev.runbook_name}</p>
                    <p className="text-xs text-slate-500 mt-0.5">
                      <span className="capitalize">{ev.event_type}</span>
                      {' · '}
                      {ev.occurred_at.slice(0, 19).replace('T', ' ')}
                      {' · by '}
                      <span className="font-medium text-slate-700">{ev.performed_by}</span>
                      {ev.duration_min > 0 && <span> · {ev.duration_min} min</span>}
                    </p>
                    {ev.notes && (
                      <p className="text-xs text-slate-400 mt-1 italic">{ev.notes}</p>
                    )}
                  </div>
                </div>
                <div className="shrink-0 flex items-center gap-2">
                  <StatusBadge state={outcomeBadge(ev.outcome)} detail={ev.outcome} />
                  <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${outcomeBg}`}>
                    {ev.outcome.toUpperCase()}
                  </span>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

// ── Page shell ────────────────────────────────────────────────────────────────

export function HardeningPage() {
  const [tab, setTab] = useState<Tab>('health');

  const tabs: { id: Tab; label: string; icon: string }[] = [
    {
      id: 'health',
      label: 'Health Checks',
      icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z',
    },
    {
      id: 'upgrades',
      label: 'Upgrade History',
      icon: 'M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12',
    },
    {
      id: 'runbooks',
      label: 'Runbook Events',
      icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Production Hardening</h1>
          <p className="text-sm text-slate-500">System health checks, upgrade compatibility auditing, and runbook drill validation.</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex overflow-x-auto border-b border-slate-200 gap-1 pb-px">
        {tabs.map((t) => {
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 px-3.5 py-2 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
                active
                  ? 'border-indigo-600 text-indigo-600 bg-indigo-50/50 rounded-t-md'
                  : 'border-transparent text-slate-600 hover:text-slate-900 hover:border-slate-300'
              }`}
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={t.icon} />
              </svg>
              {t.label}
            </button>
          );
        })}
      </div>

      <div>
        {tab === 'health' && <HealthTab />}
        {tab === 'upgrades' && <UpgradesTab />}
        {tab === 'runbooks' && <RunbooksTab />}
      </div>
    </div>
  );
}
