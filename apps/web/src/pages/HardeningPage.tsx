import { useEffect, useState } from 'react';
import { type OperationalState, EmptyState, ErrorNote, StatusBadge } from '../components/ui';
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

  if (loading) return <p className="text-ink-secondary text-sm">Loading health checks…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load health checks" onRetry={load} />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-medium text-ink">System Health</h2>
          <StatusBadge state={healthState(overall)} detail={overall} />
        </div>
        <button
          type="button"
          onClick={() => void runCheck()}
          disabled={running}
          className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent/90 disabled:opacity-50"
        >
          {running ? 'Running…' : 'Run Checks'}
        </button>
      </div>

      {checks.length === 0 ? (
        <EmptyState title="No health checks recorded">
          <p className="text-sm text-ink-secondary">Run checks to record system health state.</p>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line">
          {checks.map((c) => (
            <li key={c.id} className="flex items-center justify-between gap-4 px-4 py-3">
              <div>
                <p className="font-mono text-sm text-ink">{c.check_name}</p>
                <p className="text-xs text-ink-muted">{c.message}</p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <span className="text-xs text-ink-muted">{c.duration_ms}ms</span>
                <StatusBadge state={healthState(c.status)} detail={c.status} />
              </div>
            </li>
          ))}
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

  if (loading) return <p className="text-ink-secondary text-sm">Loading upgrade history…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load upgrade history" onRetry={() => setError(null)} />;

  return (
    <div className="space-y-4">
      <h2 className="text-sm font-medium text-ink">Upgrade History ({upgrades.length})</h2>

      {upgrades.length === 0 ? (
        <EmptyState title="No upgrades recorded">
          <p className="text-sm text-ink-secondary">Migration runs will appear here.</p>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line font-mono text-xs">
          {upgrades.map((u) => (
            <li key={u.id} className="flex items-center gap-3 px-4 py-2">
              <span className="text-ink-muted w-32 shrink-0">{u.applied_at.slice(0, 19).replace('T', ' ')}</span>
              <span className="text-ink flex-1 truncate">{u.migration_name}</span>
              <span className={`shrink-0 ${u.status === 'ok' ? 'text-green-600' : 'text-danger'}`}>{u.status}</span>
              <span className="text-ink-muted shrink-0">{u.duration_ms}ms</span>
            </li>
          ))}
        </ul>
      )}
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

  if (loading) return <p className="text-ink-secondary text-sm">Loading runbook events…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load runbook events" onRetry={load} />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-ink">Runbook Events ({events.length})</h2>
        <button
          type="button"
          onClick={() => setRecording(true)}
          className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent/90"
        >
          Record Event
        </button>
      </div>

      {recording && (
        <div className="rounded-md border border-line bg-surface p-4 space-y-3">
          <h3 className="text-sm font-medium text-ink">Record Runbook Event</h3>
          <div className="grid gap-2 sm:grid-cols-2">
            <div>
              <label className="text-xs text-ink-secondary">Runbook Name</label>
              <input
                type="text"
                value={form.runbook_name}
                onChange={(e) => setForm((f) => ({ ...f, runbook_name: e.target.value }))}
                placeholder="e.g. db-restore-drill"
                className="mt-1 w-full rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
              />
            </div>
            <div>
              <label className="text-xs text-ink-secondary">Type</label>
              <select
                value={form.event_type}
                onChange={(e) => setForm((f) => ({ ...f, event_type: e.target.value }))}
                className="mt-1 w-full rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
              >
                <option value="drill">Drill</option>
                <option value="incident">Incident</option>
                <option value="recovery">Recovery</option>
                <option value="test">Test</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-ink-secondary">Outcome</label>
              <select
                value={form.outcome}
                onChange={(e) => setForm((f) => ({ ...f, outcome: e.target.value }))}
                className="mt-1 w-full rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
              >
                <option value="pass">Pass</option>
                <option value="fail">Fail</option>
                <option value="partial">Partial</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-ink-secondary">Duration (min)</label>
              <input
                type="number"
                value={form.duration_min}
                onChange={(e) => setForm((f) => ({ ...f, duration_min: Number(e.target.value) }))}
                className="mt-1 w-full rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
              />
            </div>
          </div>
          <div>
            <label className="text-xs text-ink-secondary">Notes</label>
            <textarea
              value={form.notes}
              onChange={(e) => setForm((f) => ({ ...f, notes: e.target.value }))}
              rows={2}
              className="mt-1 w-full rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
            />
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => void record()}
              disabled={saving}
              className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent/90 disabled:opacity-50"
            >
              {saving ? 'Saving…' : 'Save'}
            </button>
            <button
              type="button"
              onClick={() => setRecording(false)}
              className="rounded-md border border-line px-3 py-1.5 text-xs text-ink-secondary hover:text-ink"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {events.length === 0 ? (
        <EmptyState title="No runbook events">
          <p className="text-sm text-ink-secondary">Record drill and incident outcomes for runbook validation.</p>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line">
          {events.map((ev) => (
            <li key={ev.id} className="flex items-center justify-between gap-4 px-4 py-3">
              <div>
                <p className="font-mono text-sm text-ink">{ev.runbook_name}</p>
                <p className="text-xs text-ink-muted">
                  {ev.event_type} · {ev.occurred_at.slice(0, 19).replace('T', ' ')} · {ev.performed_by}
                  {ev.duration_min > 0 && ` · ${ev.duration_min}min`}
                </p>
                {ev.notes && <p className="text-xs text-ink-secondary">{ev.notes}</p>}
              </div>
              <StatusBadge state={outcomeBadge(ev.outcome)} detail={ev.outcome} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── Page shell ────────────────────────────────────────────────────────────────

export function HardeningPage() {
  const [tab, setTab] = useState<Tab>('health');

  const tabs: { id: Tab; label: string }[] = [
    { id: 'health', label: 'Health Checks' },
    { id: 'upgrades', label: 'Upgrade History' },
    { id: 'runbooks', label: 'Runbook Events' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold tracking-wide text-ink">Production Hardening</h1>
        <p className="mt-1 text-sm text-ink-secondary">
          System health checks, upgrade compatibility auditing, and runbook drill validation.
        </p>
      </div>

      <div className="flex gap-1 border-b border-line">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-sm ${
              tab === t.id
                ? 'border-b-2 border-accent font-medium text-ink'
                : 'text-ink-secondary hover:text-ink'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div>
        {tab === 'health' && <HealthTab />}
        {tab === 'upgrades' && <UpgradesTab />}
        {tab === 'runbooks' && <RunbooksTab />}
      </div>
    </div>
  );
}
