import { useEffect, useState } from 'react';
import { type OperationalState, EmptyState, ErrorNote, StatusBadge } from '../components/ui';
import { type HADrill, type HAEvent, type HAMember, type HAPool, haApi } from '../api/client';

type Tab = 'pools' | 'events' | 'drills';

const PROJECT_ID = 'default'; // ponytail: per-project selector; add when project switcher exists

function poolState(state: string): OperationalState {
  const map: Record<string, OperationalState> = {
    healthy: 'Healthy',
    degraded: 'Warning',
    failed: 'Failed',
    draining: 'Updating',
  };
  return map[state] ?? 'Unknown';
}

function memberState(state: string): OperationalState {
  const map: Record<string, OperationalState> = {
    active: 'Healthy',
    draining: 'Updating',
    drained: 'Paused',
    failed: 'Failed',
    offline: 'Failed',
  };
  return map[state] ?? 'Unknown';
}

function drillState(state: string): OperationalState {
  const map: Record<string, OperationalState> = {
    pending: 'Pending',
    running: 'Running',
    passed: 'Healthy',
    failed: 'Failed',
    cancelled: 'Disabled',
  };
  return map[state] ?? 'Unknown';
}

// ── Pool Members subcomponent ────────────────────────────────────────────────────

function PoolMembersPanel({ pool }: { pool: HAPool }) {
  const [members, setMembers] = useState<HAMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const load = () => {
    setLoading(true);
    haApi
      .listMembers(PROJECT_ID, pool.id)
      .then((r) => setMembers(r.members ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [pool.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const drain = async (serverId: string) => {
    if (!window.confirm('Start drain for this server?')) return;
    try {
      await haApi.startDrain(PROJECT_ID, pool.id, serverId, 'manual drain');
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  const remove = async (id: string) => {
    if (!window.confirm('Remove this server from the pool?')) return;
    try {
      await haApi.removeMember(PROJECT_ID, pool.id, id);
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  if (loading) return <p className="text-ink-secondary text-xs">Loading members…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load members" onRetry={load} />;

  return (
    <div className="mt-3 space-y-1">
      {members.length === 0 ? (
        <p className="text-xs text-ink-muted">No members in this pool.</p>
      ) : (
        <ul className="divide-y divide-line rounded border border-line text-xs">
          {members.map((m) => (
            <li key={m.id} className="flex items-center justify-between gap-2 px-3 py-2">
              <span className="font-mono text-ink">{m.server_id}</span>
              <span className="text-ink-muted">{m.role} w:{m.weight}</span>
              <StatusBadge state={memberState(m.state)} detail={m.state} />
              <div className="flex gap-2">
                {m.state === 'active' && (
                  <button
                    type="button"
                    onClick={() => void drain(m.server_id)}
                    className="text-ink-secondary hover:text-ink"
                  >
                    Drain
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => void remove(m.id)}
                  className="text-ink-secondary hover:text-danger"
                >
                  Remove
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── Pools tab ────────────────────────────────────────────────────────────────────

function PoolsTab() {
  const [pools, setPools] = useState<HAPool[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [newName, setNewName] = useState('');
  const [newMode, setNewMode] = useState('active-passive');
  const [saving, setSaving] = useState(false);

  const load = () => {
    setLoading(true);
    haApi
      .listPools(PROJECT_ID)
      .then((r) => setPools(r.pools ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const create = async () => {
    if (!newName.trim()) return;
    setSaving(true);
    try {
      await haApi.createPool(PROJECT_ID, newName.trim(), '', newMode, 1);
      setAdding(false);
      setNewName('');
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setSaving(false);
    }
  };

  const deletePool = async (id: string) => {
    if (!window.confirm('Delete this pool? All members and events will be removed.')) return;
    try {
      await haApi.deletePool(PROJECT_ID, id);
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  if (loading) return <p className="text-ink-secondary text-sm">Loading server pools…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load pools" onRetry={load} />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-ink">Server Pools ({pools.length})</h2>
        <button
          type="button"
          onClick={() => setAdding(true)}
          className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent/90"
        >
          Create Pool
        </button>
      </div>

      {adding && (
        <div className="rounded-md border border-line bg-surface p-4 space-y-3">
          <h3 className="text-sm font-medium text-ink">Create Server Pool</h3>
          <div className="grid gap-2 sm:grid-cols-2">
            <div>
              <label className="text-xs text-ink-secondary">Name</label>
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="pool-name"
                className="mt-1 w-full rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
              />
            </div>
            <div>
              <label className="text-xs text-ink-secondary">Mode</label>
              <select
                value={newMode}
                onChange={(e) => setNewMode(e.target.value)}
                className="mt-1 w-full rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
              >
                <option value="active-passive">Active-Passive</option>
                <option value="active-active">Active-Active</option>
                <option value="canary">Canary</option>
              </select>
            </div>
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => void create()}
              disabled={saving}
              className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent/90 disabled:opacity-50"
            >
              {saving ? 'Creating…' : 'Create'}
            </button>
            <button
              type="button"
              onClick={() => { setAdding(false); setNewName(''); }}
              className="rounded-md border border-line px-3 py-1.5 text-xs text-ink-secondary hover:text-ink"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {pools.length === 0 ? (
        <EmptyState title="No server pools">
          <p className="text-sm text-ink-secondary">Create a pool to group servers for HA routing.</p>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line">
          {pools.map((pool) => (
            <li key={pool.id} className="px-4 py-3">
              <div className="flex items-center justify-between gap-4">
                <div className="min-w-0">
                  <p className="font-medium text-sm text-ink">{pool.name}</p>
                  <p className="text-xs text-ink-muted">{pool.mode} · min_healthy: {pool.min_healthy}</p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <StatusBadge state={poolState(pool.state)} detail={pool.state} />
                  <button
                    type="button"
                    onClick={() => setExpanded(expanded === pool.id ? null : pool.id)}
                    className="text-xs text-ink-secondary hover:text-ink"
                  >
                    {expanded === pool.id ? 'Hide' : 'Members'}
                  </button>
                  <button
                    type="button"
                    onClick={() => void deletePool(pool.id)}
                    className="text-xs text-ink-secondary hover:text-danger"
                  >
                    Delete
                  </button>
                </div>
              </div>
              {expanded === pool.id && <PoolMembersPanel pool={pool} />}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── Events tab ────────────────────────────────────────────────────────────────────

function EventsTab() {
  const [pools, setPools] = useState<HAPool[]>([]);
  const [selectedPool, setSelectedPool] = useState('');
  const [events, setEvents] = useState<HAEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    haApi
      .listPools(PROJECT_ID)
      .then((r) => {
        const ps = r.pools ?? [];
        setPools(ps);
        if (ps.length > 0) setSelectedPool(ps[0].id);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))));
  }, []);

  useEffect(() => {
    if (!selectedPool) return;
    setLoading(true);
    haApi
      .listEvents(PROJECT_ID, selectedPool)
      .then((r) => setEvents(r.events ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, [selectedPool]);

  const resolve = async (id: string) => {
    try {
      await haApi.resolveEvent(PROJECT_ID, selectedPool, id);
      setEvents((prev) => prev.map((ev) => ev.id === id ? { ...ev, resolved: true } : ev));
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  if (error) return <ErrorNote error={error} title="Failed to load events" onRetry={() => setError(null)} />;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <label className="text-sm text-ink-secondary">Pool</label>
        <select
          value={selectedPool}
          onChange={(e) => setSelectedPool(e.target.value)}
          className="rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
        >
          {pools.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>

      {loading ? (
        <p className="text-ink-secondary text-sm">Loading events…</p>
      ) : events.length === 0 ? (
        <EmptyState title="No failover events">
          <p className="text-sm text-ink-secondary">No HA events recorded yet.</p>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line font-mono text-xs">
          {events.map((ev) => (
            <li key={ev.id} className={`flex items-center gap-3 px-4 py-2 ${ev.resolved ? 'opacity-60' : ''}`}>
              <span className="w-32 shrink-0 text-ink-muted">{ev.occurred_at.slice(0, 19).replace('T', ' ')}</span>
              <span className="font-sans text-ink font-medium">{ev.event_type}</span>
              <span className="text-ink-secondary truncate">{ev.server_id}</span>
              <span className="text-ink-muted">{ev.triggered_by}</span>
              {!ev.resolved && (
                <button
                  type="button"
                  onClick={() => void resolve(ev.id)}
                  className="shrink-0 font-sans text-xs text-ink-secondary hover:text-ink"
                >
                  Resolve
                </button>
              )}
              {ev.resolved && <span className="shrink-0 font-sans text-xs text-ink-muted">resolved</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── Drills tab ────────────────────────────────────────────────────────────────────

function DrillsTab() {
  const [pools, setPools] = useState<HAPool[]>([]);
  const [selectedPool, setSelectedPool] = useState('');
  const [drills, setDrills] = useState<HADrill[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    haApi
      .listPools(PROJECT_ID)
      .then((r) => {
        const ps = r.pools ?? [];
        setPools(ps);
        if (ps.length > 0) setSelectedPool(ps[0].id);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))));
  }, []);

  useEffect(() => {
    if (!selectedPool) return;
    setLoading(true);
    haApi
      .listDrills(PROJECT_ID, selectedPool)
      .then((r) => setDrills(r.drills ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, [selectedPool]);

  const runDrill = async () => {
    if (!selectedPool) return;
    try {
      await haApi.createDrill(PROJECT_ID, selectedPool, 'manual', '');
      setLoading(true);
      const r = await haApi.listDrills(PROJECT_ID, selectedPool);
      setDrills(r.drills ?? []);
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setLoading(false);
    }
  };

  const complete = async (id: string, state: string) => {
    try {
      await haApi.completeDrill(PROJECT_ID, selectedPool, id, state, '');
      setDrills((prev) => prev.map((d) => d.id === id ? { ...d, state } : d));
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  if (error) return <ErrorNote error={error} title="Failed to load drills" onRetry={() => setError(null)} />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <label className="text-sm text-ink-secondary">Pool</label>
          <select
            value={selectedPool}
            onChange={(e) => setSelectedPool(e.target.value)}
            className="rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
          >
            {pools.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </div>
        <button
          type="button"
          onClick={() => void runDrill()}
          className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent/90"
        >
          Run Drill
        </button>
      </div>

      {loading ? (
        <p className="text-ink-secondary text-sm">Loading drills…</p>
      ) : drills.length === 0 ? (
        <EmptyState title="No failover drills">
          <p className="text-sm text-ink-secondary">Run a drill to test HA failover behavior.</p>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line">
          {drills.map((d) => (
            <li key={d.id} className="flex items-center justify-between gap-4 px-4 py-3">
              <div>
                <p className="text-sm text-ink">{d.drill_type} drill</p>
                <p className="text-xs text-ink-muted">{d.created_at.slice(0, 19).replace('T', ' ')} · {d.initiated_by}</p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <StatusBadge state={drillState(d.state)} detail={d.state} />
                {d.state === 'running' && (
                  <>
                    <button
                      type="button"
                      onClick={() => void complete(d.id, 'passed')}
                      className="text-xs text-ink-secondary hover:text-ink"
                    >
                      Pass
                    </button>
                    <button
                      type="button"
                      onClick={() => void complete(d.id, 'failed')}
                      className="text-xs text-ink-secondary hover:text-danger"
                    >
                      Fail
                    </button>
                  </>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── Page shell ─────────────────────────────────────────────────────────────────

export function HAPage() {
  const [tab, setTab] = useState<Tab>('pools');

  const tabs: { id: Tab; label: string }[] = [
    { id: 'pools', label: 'Server Pools' },
    { id: 'events', label: 'Failover Events' },
    { id: 'drills', label: 'Drills' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold tracking-wide text-ink">High Availability</h1>
        <p className="mt-1 text-sm text-ink-secondary">
          Manage server pools, monitor failover events, and run HA drills.
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
        {tab === 'pools' && <PoolsTab />}
        {tab === 'events' && <EventsTab />}
        {tab === 'drills' && <DrillsTab />}
      </div>
    </div>
  );
}
