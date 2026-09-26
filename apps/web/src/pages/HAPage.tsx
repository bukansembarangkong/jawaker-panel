import { useEffect, useState } from 'react';
import { goeyToast } from 'goey-toast';
import { type OperationalState, ErrorNote, StatusBadge, Modal, ConfirmModal, inputClass, primaryButtonClass, secondaryButtonClass } from '../components/ui';
import { type HADrill, type HAEvent, type HAMember, type HAPool, haApi } from '../api/client';
import { useFirstProjectId } from '../hooks/useFirstProjectId';

type Tab = 'pools' | 'events' | 'drills';

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

function modeBadge(mode: string) {
  const colors: Record<string, string> = {
    'active-passive': 'bg-blue-100 text-blue-700',
    'active-active': 'bg-purple-100 text-purple-700',
    'canary': 'bg-amber-100 text-amber-700',
  };
  return (
    <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${colors[mode] ?? 'bg-slate-100 text-slate-600'}`}>
      {mode}
    </span>
  );
}

const thClass = 'px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50';
const tdClass = 'px-4 py-3 text-sm text-slate-800';

function PoolMembersPanel({ pool }: { pool: HAPool }) {
  const projectId = useFirstProjectId();
  const [members, setMembers] = useState<HAMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [confirmState, setConfirmState] = useState<{ open: boolean; message: string; onConfirm: () => void }>({ open: false, message: '', onConfirm: () => {} });

  const load = () => {
    if (!projectId) return;
    setLoading(true);
    haApi
      .listMembers(projectId, pool.id)
      .then((r) => setMembers(r.members ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { if (projectId) load(); }, [pool.id, projectId]); // eslint-disable-line react-hooks/exhaustive-deps

  const drain = async (serverId: string) => {
    if (!projectId) return;
    setConfirmState({
      open: true,
      message: 'Start drain for this server?',
      onConfirm: async () => {
        try {
          await haApi.startDrain(projectId, pool.id, serverId, 'manual drain');
          goeyToast.success('Member drain started');
          load();
        } catch (e) {
          const err = e instanceof Error ? e : new Error(String(e));
          goeyToast.error(`Failed to drain member: ${err.message}`);
          setError(err);
        }
      },
    });
  };

  const remove = async (id: string) => {
    if (!projectId) return;
    setConfirmState({
      open: true,
      message: 'Remove this server from the pool?',
      onConfirm: async () => {
        try {
          await haApi.removeMember(projectId, pool.id, id);
          goeyToast.success('Member removed from pool');
          load();
        } catch (e) {
          const err = e instanceof Error ? e : new Error(String(e));
          goeyToast.error(`Failed to remove member: ${err.message}`);
          setError(err);
        }
      },
    });
  };

  if (loading) return <p className="text-slate-400 text-xs py-2">Loading members…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load members" onRetry={load} />;

  return (
    <div className="mt-4 border-t border-slate-100 pt-4">
      <ConfirmModal
        isOpen={confirmState.open}
        onClose={() => setConfirmState(s => ({ ...s, open: false }))}
        onConfirm={confirmState.onConfirm}
        title="Are you sure?"
        message={confirmState.message}
        confirmLabel="Yes, proceed"
        danger
      />
      <p className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">Members ({members.length})</p>
      {members.length === 0 ? (
        <p className="text-xs text-slate-400 py-2">No members in this pool.</p>
      ) : (
        <div className="rounded-lg border border-slate-200 overflow-hidden">
          <table className="w-full">
            <thead>
              <tr>
                <th className={thClass}>Server</th>
                <th className={thClass}>Role</th>
                <th className={thClass}>Weight</th>
                <th className={thClass}>Status</th>
                <th className={thClass}></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {members.map((m) => (
                <tr key={m.id}>
                  <td className="px-4 py-3 font-mono text-xs text-slate-800">{m.server_id}</td>
                  <td className={tdClass}>{m.role}</td>
                  <td className={tdClass}>{m.weight}</td>
                  <td className="px-4 py-3">
                    <StatusBadge state={memberState(m.state)} detail={m.state} />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-2 justify-end">
                      {m.state === 'active' && (
                        <button
                          type="button"
                          onClick={() => void drain(m.server_id)}
                          className="rounded border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50"
                        >
                          Drain
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => void remove(m.id)}
                        className="rounded bg-red-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-red-700"
                      >
                        Remove
                      </button>
                    </div>
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

function PoolsTab() {
  const projectId = useFirstProjectId();
  const [pools, setPools] = useState<HAPool[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [newName, setNewName] = useState('');
  const [newMode, setNewMode] = useState('active-passive');
  const [saving, setSaving] = useState(false);
  const [confirmState, setConfirmState] = useState<{ open: boolean; message: string; onConfirm: () => void }>({ open: false, message: '', onConfirm: () => {} });

  const load = () => {
    if (!projectId) return;
    setLoading(true);
    haApi
      .listPools(projectId)
      .then((r) => setPools(r.pools ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { if (projectId) load(); }, [projectId]); // eslint-disable-line react-hooks/exhaustive-deps

  const create = async () => {
    if (!projectId) return;
    if (!newName.trim()) return;
    setSaving(true);
    try {
      await haApi.createPool(projectId, newName.trim(), '', newMode, 1);
      goeyToast.success('Server pool created');
      setAdding(false);
      setNewName('');
      load();
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      goeyToast.error(`Failed to create pool: ${err.message}`);
      setError(err);
    } finally {
      setSaving(false);
    }
  };

  const deletePool = async (id: string) => {
    if (!projectId) return;
    setConfirmState({
      open: true,
      message: 'Delete this pool? All members and events will be removed.',
      onConfirm: async () => {
        try {
          await haApi.deletePool(projectId, id);
          goeyToast.success('Server pool deleted');
          load();
        } catch (e) {
          const err = e instanceof Error ? e : new Error(String(e));
          goeyToast.error(`Failed to delete pool: ${err.message}`);
          setError(err);
        }
      },
    });
  };

  if (loading) return <p className="text-slate-500 text-sm">Loading server pools…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load pools" onRetry={load} />;

  return (
    <div className="space-y-6">
      <ConfirmModal
        isOpen={confirmState.open}
        onClose={() => setConfirmState(s => ({ ...s, open: false }))}
        onConfirm={confirmState.onConfirm}
        title="Are you sure?"
        message={confirmState.message}
        confirmLabel="Yes, proceed"
        danger
      />

      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-slate-900">Server Pools ({pools.length})</h2>
          <p className="text-xs text-slate-500">Group servers for high availability, health checking, and automatic failover.</p>
        </div>
        <button
          type="button"
          onClick={() => setAdding(true)}
          className={primaryButtonClass}
        >
          + Create Pool
        </button>
      </div>

      <Modal
        isOpen={adding}
        onClose={() => { setAdding(false); setNewName(''); }}
        title="Create Server Pool"
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void create();
          }}
        >
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className="text-xs font-medium text-slate-700">Name</label>
              <input
                type="text"
                required
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="pool-name"
                className={inputClass}
              />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-700">Mode</label>
              <select
                value={newMode}
                onChange={(e) => setNewMode(e.target.value)}
                className={inputClass}
              >
                <option value="active-passive">Active-Passive</option>
                <option value="active-active">Active-Active</option>
                <option value="canary">Canary</option>
              </select>
            </div>
          </div>
          <div className="flex gap-2 justify-end pt-2">
            <button
              type="button"
              onClick={() => { setAdding(false); setNewName(''); }}
              className={secondaryButtonClass}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !newName.trim()}
              className={primaryButtonClass}
            >
              {saving ? 'Creating…' : 'Create'}
            </button>
          </div>
        </form>
      </Modal>

      {pools.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
          <span className="text-4xl">🔄</span>
          <h3 className="mt-2 text-base font-semibold text-slate-900">No server pools</h3>
          <p className="mt-1 text-sm text-slate-500">Create a pool to group servers for HA routing.</p>
        </div>
      ) : (
        <div className="grid gap-4">
          {pools.map((pool) => (
            <div key={pool.id} className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-semibold text-slate-900">{pool.name}</h3>
                    {modeBadge(pool.mode)}
                    <StatusBadge state={poolState(pool.state)} detail={pool.state} />
                  </div>
                  <p className="text-xs text-slate-500 mt-1">
                    min_healthy: {pool.min_healthy}
                    {pool.description ? ` · ${pool.description}` : ''}
                  </p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => setExpanded(expanded === pool.id ? null : pool.id)}
                    className={secondaryButtonClass}
                  >
                    {expanded === pool.id ? 'Hide Members' : 'View Members'}
                  </button>
                  <button
                    type="button"
                    onClick={() => void deletePool(pool.id)}
                    className="rounded-lg bg-red-600 px-3 py-2 text-sm font-medium text-white hover:bg-red-700"
                  >
                    Delete
                  </button>
                </div>
              </div>
              {expanded === pool.id && <PoolMembersPanel pool={pool} />}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function EventsTab() {
  const projectId = useFirstProjectId();
  const [pools, setPools] = useState<HAPool[]>([]);
  const [selectedPool, setSelectedPool] = useState('');
  const [events, setEvents] = useState<HAEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    if (!projectId) return;
    haApi
      .listPools(projectId)
      .then((r) => {
        const ps = r.pools ?? [];
        setPools(ps);
        if (ps.length > 0) setSelectedPool(ps[0].id);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))));
  }, [projectId]);

  useEffect(() => {
    if (!projectId || !selectedPool) return;
    setLoading(true);
    haApi
      .listEvents(projectId, selectedPool)
      .then((r) => setEvents(r.events ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, [projectId, selectedPool]);

  const resolve = async (id: string) => {
    if (!projectId) return;
    try {
      await haApi.resolveEvent(projectId, selectedPool, id);
      goeyToast.success('Failover event resolved');
      setEvents((prev) => prev.map((ev) => ev.id === id ? { ...ev, resolved: true } : ev));
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      goeyToast.error(`Failed to resolve event: ${err.message}`);
      setError(err);
    }
  };

  if (error) return <ErrorNote error={error} title="Failed to load events" onRetry={() => setError(null)} />;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <label className="text-sm font-medium text-slate-700">Pool</label>
        <select
          value={selectedPool}
          onChange={(e) => setSelectedPool(e.target.value)}
          className={inputClass}
        >
          {pools.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        {loading ? (
          <p className="p-6 text-sm text-slate-500">Loading events…</p>
        ) : events.length === 0 ? (
          <div className="flex flex-col items-center py-12 gap-2 text-center">
            <span className="text-3xl">📋</span>
            <p className="font-medium text-slate-700">No failover events</p>
            <p className="text-sm text-slate-500">No HA events recorded yet.</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr>
                <th className={thClass}>Occurred</th>
                <th className={thClass}>Type</th>
                <th className={thClass}>Server</th>
                <th className={thClass}>Triggered By</th>
                <th className={thClass}>Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {events.map((ev) => (
                <tr key={ev.id} className={ev.resolved ? 'opacity-60' : ''}>
                  <td className="px-4 py-3 font-mono text-xs text-slate-500">
                    {ev.occurred_at.slice(0, 19).replace('T', ' ')}
                  </td>
                  <td className={`${tdClass} font-medium`}>{ev.event_type}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-700 truncate">{ev.server_id}</td>
                  <td className="px-4 py-3 text-xs text-slate-500">{ev.triggered_by}</td>
                  <td className="px-4 py-3">
                    {!ev.resolved ? (
                      <button
                        type="button"
                        onClick={() => void resolve(ev.id)}
                        className="rounded-lg border border-slate-200 bg-white px-3 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50"
                      >
                        Resolve
                      </button>
                    ) : (
                      <span className="rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-500">
                        Resolved
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function DrillsTab() {
  const projectId = useFirstProjectId();
  const [pools, setPools] = useState<HAPool[]>([]);
  const [selectedPool, setSelectedPool] = useState('');
  const [drills, setDrills] = useState<HADrill[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    if (!projectId) return;
    haApi
      .listPools(projectId)
      .then((r) => {
        const ps = r.pools ?? [];
        setPools(ps);
        if (ps.length > 0) setSelectedPool(ps[0].id);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))));
  }, [projectId]);

  useEffect(() => {
    if (!projectId || !selectedPool) return;
    setLoading(true);
    haApi
      .listDrills(projectId, selectedPool)
      .then((r) => setDrills(r.drills ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, [projectId, selectedPool]);

  const runDrill = async () => {
    if (!projectId || !selectedPool) return;
    try {
      await haApi.createDrill(projectId, selectedPool, 'manual', '');
      goeyToast.success('Drill triggered');
      setLoading(true);
      const r = await haApi.listDrills(projectId, selectedPool);
      setDrills(r.drills ?? []);
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      goeyToast.error(`Failed to run drill: ${err.message}`);
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  const complete = async (id: string, state: string) => {
    if (!projectId) return;
    try {
      await haApi.completeDrill(projectId, selectedPool, id, state, '');
      goeyToast.success(`Drill marked as ${state}`);
      setDrills((prev) => prev.map((d) => d.id === id ? { ...d, state } : d));
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      goeyToast.error(`Failed to complete drill: ${err.message}`);
      setError(err);
    }
  };

  if (error) return <ErrorNote error={error} title="Failed to load drills" onRetry={() => setError(null)} />;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <label className="text-sm font-medium text-slate-700">Pool</label>
          <select
            value={selectedPool}
            onChange={(e) => setSelectedPool(e.target.value)}
            className={inputClass}
          >
            {pools.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </div>
        <button
          type="button"
          onClick={() => void runDrill()}
          className={primaryButtonClass}
        >
          Run Drill
        </button>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        {loading ? (
          <p className="p-6 text-sm text-slate-500">Loading drills…</p>
        ) : drills.length === 0 ? (
          <div className="flex flex-col items-center py-12 gap-2 text-center">
            <span className="text-3xl">🧪</span>
            <p className="font-medium text-slate-700">No failover drills</p>
            <p className="text-sm text-slate-500">Run a drill to test HA failover behavior.</p>
          </div>
        ) : (
          <ul className="divide-y divide-slate-100">
            {drills.map((d) => (
              <li key={d.id} className="flex items-center justify-between gap-4 px-6 py-4">
                <div>
                  <p className="text-sm font-semibold text-slate-900">{d.drill_type} drill</p>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {d.created_at.slice(0, 19).replace('T', ' ')} · {d.initiated_by}
                  </p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <StatusBadge state={drillState(d.state)} detail={d.state} />
                  {d.state === 'running' && (
                    <div className="flex gap-2">
                      <button
                        type="button"
                        onClick={() => void complete(d.id, 'passed')}
                        className="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-emerald-700"
                      >
                        Pass
                      </button>
                      <button
                        type="button"
                        onClick={() => void complete(d.id, 'failed')}
                        className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700"
                      >
                        Fail
                      </button>
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export function HAPage() {
  const [tab, setTab] = useState<Tab>('pools');

  const tabs: { id: Tab; label: string }[] = [
    { id: 'pools', label: 'Server Pools' },
    { id: 'events', label: 'Failover Events' },
    { id: 'drills', label: 'Drills' },
  ];

  const tabClass = (t: Tab) =>
    `px-4 py-2 text-sm font-medium transition-colors ${
      tab === t
        ? 'border-b-2 border-indigo-600 text-indigo-600'
        : 'text-slate-500 hover:text-slate-700'
    }`;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">High Availability</h1>
          <p className="text-sm text-slate-500">
            Manage server pools, monitor failover events, and run HA drills.
          </p>
        </div>
      </div>

      <div className="flex gap-1 border-b border-slate-200">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={tabClass(t.id)}
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
