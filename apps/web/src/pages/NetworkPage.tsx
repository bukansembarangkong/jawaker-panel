import { useCallback, useEffect, useState } from 'react';
import { goeyToast } from 'goey-toast';

import {
  networkApi,
  isStepUpRequired,
  type FirewallRule,
  type PortForward,
  type NetworkZone,
  type WireGuardPeer,
  type NetworkApplyLog,
  type ListeningPort,
  type NetDiagResult,
} from '../api/client';
import { StepUpPrompt } from '../components/StepUpPrompt';
import {
  ErrorNote,
  Field,
  Modal,
} from '../components/ui';

type Tab = 'firewall' | 'forwards' | 'zones' | 'wireguard' | 'diag' | 'applylog';

function formatTs(v: string | null | undefined): string {
  if (!v) return '-';
  try { return new Date(v).toLocaleString(); } catch { return v; }
}

function toError(e: unknown): Error {
  return e instanceof Error ? e : new Error(String(e));
}

function truncateKey(key: string, head = 8, tail = 8): string {
  if (!key) return '-';
  if (key.length <= head + tail + 3) return key;
  return `${key.slice(0, head)}…${key.slice(-tail)}`;
}

interface ServerOption { id: string; name: string; }

export function NetworkPage() {
  const [servers, setServers] = useState<ServerOption[]>([]);
  const [serverId, setServerId] = useState('');
  const [tab, setTab] = useState<Tab>('firewall');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [stepUpPending, setStepUpPending] = useState(false);
  const [stepUpAction, setStepUpAction] = useState<(() => Promise<void>) | null>(null);

  // Firewall tab
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [liveChains, setLiveChains] = useState<string | null>(null);
  const [liveLoading, setLiveLoading] = useState(false);
  const [showCreateRule, setShowCreateRule] = useState(false);
  const [newRule, setNewRule] = useState({
    chain: 'INPUT', priority: '100', protocol: 'tcp',
    source_cidr: '', dest_cidr: '', dest_port_min: '', dest_port_max: '',
    action: 'ACCEPT', enabled: true, description: '',
  });

  // Port forwards tab
  const [forwards, setForwards] = useState<PortForward[]>([]);
  const [showCreateForward, setShowCreateForward] = useState(false);
  const [newFwd, setNewFwd] = useState({
    protocol: 'tcp', listen_address: '', listen_port: '',
    dest_address: '', dest_port: '', description: '',
  });

  // Zones tab
  const [zones, setZones] = useState<NetworkZone[]>([]);
  const [showCreateZone, setShowCreateZone] = useState(false);
  const [newZone, setNewZone] = useState({ name: '', kind: 'internal', interfaces: '' });

  // WireGuard tab
  const [peers, setPeers] = useState<WireGuardPeer[]>([]);
  const [showCreatePeer, setShowCreatePeer] = useState(false);
  const [newPeer, setNewPeer] = useState({
    public_key: '', label: '', allowed_ips: '', endpoint: '',
    persistent_keepalive: '25', enabled: true,
  });

  // Diagnostics tab
  const [diagTarget, setDiagTarget] = useState('');
  const [diagMode, setDiagMode] = useState<'ping' | 'trace'>('ping');
  const [diagRunning, setDiagRunning] = useState(false);
  const [diagResult, setDiagResult] = useState<NetDiagResult | null>(null);
  const [ports, setPorts] = useState<ListeningPort[]>([]);
  const [portsLoading, setPortsLoading] = useState(false);

  // Apply log tab
  const [applyLog, setApplyLog] = useState<NetworkApplyLog[]>([]);

  useEffect(() => {
    import('../api/client').then(({ api }) => {
      api.listServers().then((r) => {
        const list = r.servers ?? [];
        setServers(list.map((s: { id: string; name: string }) => ({ id: s.id, name: s.name })));
        if (list.length) setServerId(list[0].id);
      }).catch((e: unknown) => setError(toError(e)));
    });
  }, []);

  const loadData = useCallback(() => {
    if (!serverId) return;
    setLoading(true);
    setError(null);
    Promise.all([
      networkApi.listRules(serverId),
      networkApi.listForwards(serverId),
      networkApi.listZones(serverId),
      networkApi.listPeers(serverId),
      networkApi.listApplyLog(serverId),
    ]).then(([r, f, z, p, al]) => {
      setRules(r.rules ?? []);
      setForwards(f.forwards ?? []);
      setZones(z.zones ?? []);
      setPeers(p.peers ?? []);
      setApplyLog(al.logs ?? []);
    }).catch((e: unknown) => setError(toError(e)))
      .finally(() => setLoading(false));
  }, [serverId]);

  useEffect(() => { loadData(); }, [loadData]);

  function withStepUp(fn: () => Promise<void>) {
    return () => fn().catch((err: unknown) => {
      if (isStepUpRequired(err)) {
        setStepUpAction(() => fn);
        setStepUpPending(true);
      } else {
        const e = toError(err);
        goeyToast.error(`Failed: ${e.message}`);
        setError(e);
      }
    });
  }

  // ─── Firewall actions ─────────────────────────────────────────────────────
  async function applyFirewall() {
    await networkApi.applyFirewall(serverId);
    goeyToast.success('Firewall applied to server');
    loadData();
  }

  async function doLoadLive() {
    setLiveLoading(true);
    setLiveChains(null);
    try {
      const r = await networkApi.getLiveFirewall(serverId);
      const text = (r.chains ?? []).map((c) =>
        `Table: ${c.table}  Chain: ${c.chain}  Policy: ${c.policy ?? '-'}\n` +
        (c.rules ?? []).map((rule) =>
          `  ${rule.num}  ${rule.target}  ${rule.protocol}  ${rule.source}  ${rule.destination}  ${rule.options ?? ''}`
        ).join('\n')
      ).join('\n\n');
      setLiveChains(text || '(empty)');
    } catch (e) {
      setError(toError(e));
    } finally {
      setLiveLoading(false);
    }
  }

  async function handleCreateRule() {
    try {
      await networkApi.createRule(serverId, {
        chain: newRule.chain,
        priority: newRule.priority ? parseInt(newRule.priority, 10) : undefined,
        protocol: newRule.protocol || undefined,
        source_cidr: newRule.source_cidr || undefined,
        dest_cidr: newRule.dest_cidr || undefined,
        dest_port_min: newRule.dest_port_min ? parseInt(newRule.dest_port_min, 10) : undefined,
        dest_port_max: newRule.dest_port_max ? parseInt(newRule.dest_port_max, 10) : undefined,
        action: newRule.action,
        enabled: newRule.enabled,
        description: newRule.description || undefined,
      });
      goeyToast.success('Firewall rule created');
      setShowCreateRule(false);
      setNewRule({ chain: 'INPUT', priority: '100', protocol: 'tcp', source_cidr: '', dest_cidr: '', dest_port_min: '', dest_port_max: '', action: 'ACCEPT', enabled: true, description: '' });
      loadData();
    } catch (err) {
      const e = toError(err);
      goeyToast.error(`Failed: ${e.message}`);
      setError(e);
    }
  }

  // ─── Port Forwards ────────────────────────────────────────────────────────
  async function handleCreateForward() {
    try {
      await networkApi.createForward(serverId, {
        protocol: newFwd.protocol,
        listen_address: newFwd.listen_address || undefined,
        listen_port: parseInt(newFwd.listen_port, 10),
        dest_address: newFwd.dest_address,
        dest_port: parseInt(newFwd.dest_port, 10),
        description: newFwd.description || undefined,
      });
      goeyToast.success('Port forward created');
      setShowCreateForward(false);
      setNewFwd({ protocol: 'tcp', listen_address: '', listen_port: '', dest_address: '', dest_port: '', description: '' });
      loadData();
    } catch (err) {
      const e = toError(err);
      goeyToast.error(`Failed: ${e.message}`);
      setError(e);
    }
  }

  // ─── Zones ────────────────────────────────────────────────────────────────
  async function handleCreateZone() {
    try {
      await networkApi.createZone(serverId, {
        name: newZone.name,
        kind: newZone.kind || undefined,
        interfaces: newZone.interfaces || undefined,
      });
      goeyToast.success('Network zone created');
      setShowCreateZone(false);
      setNewZone({ name: '', kind: 'internal', interfaces: '' });
      loadData();
    } catch (err) {
      const e = toError(err);
      goeyToast.error(`Failed: ${e.message}`);
      setError(e);
    }
  }

  // ─── WireGuard ────────────────────────────────────────────────────────────
  async function handleCreatePeer() {
    try {
      await networkApi.createPeer(serverId, {
        public_key: newPeer.public_key,
        label: newPeer.label || undefined,
        allowed_ips: newPeer.allowed_ips || undefined,
        endpoint: newPeer.endpoint || undefined,
        persistent_keepalive: newPeer.persistent_keepalive ? parseInt(newPeer.persistent_keepalive, 10) : undefined,
        enabled: newPeer.enabled,
      });
      goeyToast.success('WireGuard peer created');
      setShowCreatePeer(false);
      setNewPeer({ public_key: '', label: '', allowed_ips: '', endpoint: '', persistent_keepalive: '25', enabled: true });
      loadData();
    } catch (err) {
      const e = toError(err);
      goeyToast.error(`Failed: ${e.message}`);
      setError(e);
    }
  }

  // ─── Diagnostics ──────────────────────────────────────────────────────────
  async function runDiag() {
    setDiagRunning(true);
    setDiagResult(null);
    try {
      const r = await networkApi.runDiag(serverId, { target: diagTarget, mode: diagMode });
      setDiagResult(r.result);
    } catch (e) {
      setError(toError(e));
    } finally {
      setDiagRunning(false);
    }
  }

  async function loadPorts() {
    setPortsLoading(true);
    try {
      const r = await networkApi.getPortInventory(serverId);
      setPorts(r.ports ?? []);
    } catch (e) {
      setError(toError(e));
    } finally {
      setPortsLoading(false);
    }
  }

  const tabs: { id: Tab; label: string; icon: string }[] = [
    {
      id: 'firewall',
      label: 'Firewall Rules',
      icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
    },
    {
      id: 'forwards',
      label: 'Port Forwards',
      icon: 'M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4',
    },
    {
      id: 'zones',
      label: 'Zones',
      icon: 'M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10',
    },
    {
      id: 'wireguard',
      label: 'WireGuard',
      icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
    },
    {
      id: 'diag',
      label: 'Diagnostics',
      icon: 'M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z',
    },
    {
      id: 'applylog',
      label: 'Apply Log',
      icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2',
    },
  ];

  if (!serverId && servers.length === 0 && !loading) {
    return (
      <div className="space-y-6">
        <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
          <span className="text-4xl mb-3 block">🌐</span>
          <h2 className="text-base font-semibold text-slate-900">No servers available</h2>
          <p className="text-sm text-slate-500 mt-1">Enroll a server first to configure networking and firewall rules.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Networking & Firewall</h1>
          <p className="text-sm text-slate-500">Manage packet filtering, NAT port forwarding, WireGuard VPN tunnels, and network telemetry.</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <label htmlFor="server-select" className="text-xs font-medium text-slate-500">Target Server:</label>
            <select
              id="server-select"
              className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-800 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
              value={serverId}
              onChange={(e) => setServerId(e.target.value)}
              aria-label="Select target server"
            >
              {servers.map((s) => (
                <option key={s.id} value={s.id}>{s.name}</option>
              ))}
            </select>
          </div>
          <button
            type="button"
            onClick={withStepUp(applyFirewall)}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all flex items-center gap-1.5"
          >
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
            Apply to Server
          </button>
        </div>
      </div>

      {error && <ErrorNote error={error} onRetry={loadData} />}

      {stepUpPending && (
        <StepUpPrompt
          onElevated={() => {
            setStepUpPending(false);
            if (stepUpAction) void stepUpAction();
          }}
          onCancel={() => { setStepUpPending(false); setStepUpAction(null); }}
        />
      )}

      {/* Navigation Tabs */}
      <div className="flex overflow-x-auto border-b border-slate-200 gap-1 pb-px">
        {tabs.map((t) => {
          const active = tab === t.id;
          return (
            <button
              key={t.id}
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

      {loading && <p className="text-sm text-slate-500">Syncing network configuration…</p>}

      {/* ─── FIREWALL TAB ─── */}
      {tab === 'firewall' && (
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-5">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between pb-4 border-b border-slate-100">
              <div>
                <h2 className="text-base font-semibold text-slate-900">Firewall Rules ({rules.length})</h2>
                <p className="text-xs text-slate-500">Netfilter iptables packet rules configured for this node.</p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  className="rounded-lg border border-slate-200 bg-white px-3.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-all"
                  onClick={() => { void doLoadLive(); }}
                >
                  {liveLoading ? 'Reading iptables…' : 'Read Live State'}
                </button>
                <button
                  type="button"
                  className="rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
                  onClick={() => setShowCreateRule(true)}
                >
                  + Add Rule
                </button>
              </div>
            </div>

            {liveChains != null && (
              <div className="rounded-lg border border-slate-200 bg-slate-900 p-4 text-xs font-mono text-slate-100 overflow-x-auto">
                <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800 text-slate-400">
                  <span>Live Kernel iptables State</span>
                  <button type="button" onClick={() => setLiveChains(null)} className="text-slate-400 hover:text-white">✕ Close</button>
                </div>
                <pre>{liveChains}</pre>
              </div>
            )}

            {rules.length === 0 && !loading ? (
              <div className="py-12 text-center">
                <span className="text-4xl mb-2 block">🛡️</span>
                <h3 className="text-sm font-semibold text-slate-900">No firewall rules defined</h3>
                <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">Create rules to allow or drop traffic according to ports, protocols, and CIDRs.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 text-xs font-semibold text-slate-500 uppercase tracking-wider">
                      <th className="pb-3 pr-4">Chain</th>
                      <th className="pb-3 pr-4">Protocol</th>
                      <th className="pb-3 pr-4">Source CIDR</th>
                      <th className="pb-3 pr-4">Port Range</th>
                      <th className="pb-3 pr-4">Action</th>
                      <th className="pb-3 pr-4">State</th>
                      <th className="pb-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {rules.map((rule) => {
                      const isAllow = rule.action.toUpperCase() === 'ACCEPT';
                      const portRange = rule.dest_port_min > 0
                        ? (rule.dest_port_max && rule.dest_port_max !== rule.dest_port_min
                            ? `${rule.dest_port_min}–${rule.dest_port_max}`
                            : `${rule.dest_port_min}`)
                        : 'Any';

                      return (
                        <tr key={rule.id} className="hover:bg-slate-50/60 transition-colors">
                          <td className="py-3 pr-4 font-mono text-xs font-semibold text-slate-700">{rule.chain}</td>
                          <td className="py-3 pr-4">
                            <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-slate-100 text-slate-700 border border-slate-200 uppercase">
                              {rule.protocol}
                            </span>
                          </td>
                          <td className="py-3 pr-4 font-mono text-xs text-slate-600">{rule.source_cidr || '0.0.0.0/0'}</td>
                          <td className="py-3 pr-4 font-mono text-xs text-slate-800">{portRange}</td>
                          <td className="py-3 pr-4">
                            <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                              isAllow
                                ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                                : 'bg-red-50 text-red-700 border border-red-200'
                            }`}>
                              {rule.action}
                            </span>
                          </td>
                          <td className="py-3 pr-4">
                            <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${
                              rule.enabled ? 'bg-slate-100 text-slate-700' : 'bg-amber-50 text-amber-700'
                            }`}>
                              {rule.state || (rule.enabled ? 'Active' : 'Disabled')}
                            </span>
                          </td>
                          <td className="py-3 text-right">
                            <button
                              type="button"
                              className="rounded-lg bg-red-600 px-3 py-1 text-xs font-medium text-white hover:bg-red-700 transition-all"
                              onClick={withStepUp(async () => {
                                await networkApi.deleteRule(serverId, rule.id);
                                goeyToast.success('Firewall rule deleted');
                                loadData();
                              })}
                            >
                              Delete
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <Modal
            isOpen={showCreateRule}
            onClose={() => setShowCreateRule(false)}
            title="New Firewall Rule"
          >
            <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); void handleCreateRule(); }}>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Chain">
                  <select
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
                    value={newRule.chain}
                    onChange={(e) => setNewRule({ ...newRule, chain: e.target.value })}
                  >
                    {['INPUT', 'OUTPUT', 'FORWARD'].map((c) => <option key={c}>{c}</option>)}
                  </select>
                </Field>
                <Field label="Priority">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
                    value={newRule.priority}
                    type="number"
                    onChange={(e) => setNewRule({ ...newRule, priority: e.target.value })}
                  />
                </Field>
                <Field label="Protocol">
                  <select
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
                    value={newRule.protocol}
                    onChange={(e) => setNewRule({ ...newRule, protocol: e.target.value })}
                  >
                    {['tcp', 'udp', 'icmp', 'all'].map((p) => <option key={p}>{p}</option>)}
                  </select>
                </Field>
                <Field label="Action">
                  <select
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
                    value={newRule.action}
                    onChange={(e) => setNewRule({ ...newRule, action: e.target.value })}
                  >
                    {['ACCEPT', 'DROP', 'REJECT'].map((a) => <option key={a}>{a}</option>)}
                  </select>
                </Field>
                <Field label="Source CIDR">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 font-mono text-xs"
                    placeholder="0.0.0.0/0"
                    value={newRule.source_cidr}
                    onChange={(e) => setNewRule({ ...newRule, source_cidr: e.target.value })}
                  />
                </Field>
                <Field label="Dest CIDR">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 font-mono text-xs"
                    placeholder="0.0.0.0/0"
                    value={newRule.dest_cidr}
                    onChange={(e) => setNewRule({ ...newRule, dest_cidr: e.target.value })}
                  />
                </Field>
                <Field label="Dest Port Min">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 font-mono text-xs"
                    type="number"
                    min="1"
                    max="65535"
                    value={newRule.dest_port_min}
                    onChange={(e) => setNewRule({ ...newRule, dest_port_min: e.target.value })}
                  />
                </Field>
                <Field label="Dest Port Max">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 font-mono text-xs"
                    type="number"
                    min="1"
                    max="65535"
                    value={newRule.dest_port_max}
                    onChange={(e) => setNewRule({ ...newRule, dest_port_max: e.target.value })}
                  />
                </Field>
                <Field label="Description">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
                    value={newRule.description}
                    onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
                  />
                </Field>
                <div className="flex items-center gap-2 pt-6">
                  <input
                    id="rule-enabled"
                    type="checkbox"
                    className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 h-4 w-4"
                    checked={newRule.enabled}
                    onChange={(e) => setNewRule({ ...newRule, enabled: e.target.checked })}
                  />
                  <label htmlFor="rule-enabled" className="text-sm font-medium text-slate-700">Enabled</label>
                </div>
              </div>
              <div className="flex gap-2 justify-end pt-3 border-t border-slate-100">
                <button
                  type="button"
                  className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all"
                  onClick={() => setShowCreateRule(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
                >
                  Create Rule
                </button>
              </div>
            </form>
          </Modal>
        </div>
      )}

      {/* ─── PORT FORWARDS TAB ─── */}
      {tab === 'forwards' && (
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-5">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between pb-4 border-b border-slate-100">
              <div>
                <h2 className="text-base font-semibold text-slate-900">NAT Port Forwards ({forwards.length})</h2>
                <p className="text-xs text-slate-500">Route inbound public traffic directly into internal services and containers.</p>
              </div>
              <button
                type="button"
                className="rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
                onClick={() => setShowCreateForward(true)}
              >
                + Add Forward
              </button>
            </div>

            {forwards.length === 0 && !loading ? (
              <div className="py-12 text-center">
                <span className="text-4xl mb-2 block">🔀</span>
                <h3 className="text-sm font-semibold text-slate-900">No port forwards configured</h3>
                <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">Map external ports to destination IPs and internal ports.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 text-xs font-semibold text-slate-500 uppercase tracking-wider">
                      <th className="pb-3 pr-4">Protocol</th>
                      <th className="pb-3 pr-4">Listen Socket</th>
                      <th className="pb-3 pr-4">Destination Target</th>
                      <th className="pb-3 pr-4">State</th>
                      <th className="pb-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {forwards.map((f) => (
                      <tr key={f.id} className="hover:bg-slate-50/60 transition-colors">
                        <td className="py-3 pr-4">
                          <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-slate-100 text-slate-700 border border-slate-200 uppercase">
                            {f.protocol}
                          </span>
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs text-slate-800">
                          {f.listen_address ? `${f.listen_address}:` : '0.0.0.0:'}{f.listen_port}
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs text-indigo-600 font-medium">
                          {f.dest_address}:{f.dest_port}
                        </td>
                        <td className="py-3 pr-4">
                          <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
                            {f.state || 'Active'}
                          </span>
                        </td>
                        <td className="py-3 text-right">
                          <button
                            type="button"
                            className="rounded-lg bg-red-600 px-3 py-1 text-xs font-medium text-white hover:bg-red-700 transition-all"
                            onClick={withStepUp(async () => {
                              await networkApi.deleteForward(serverId, f.id);
                              goeyToast.success('Port forward deleted');
                              loadData();
                            })}
                          >
                            Delete
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <Modal
            isOpen={showCreateForward}
            onClose={() => setShowCreateForward(false)}
            title="New Port Forward"
          >
            <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); void handleCreateForward(); }}>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Protocol">
                  <select
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
                    value={newFwd.protocol}
                    onChange={(e) => setNewFwd({ ...newFwd, protocol: e.target.value })}
                  >
                    <option>tcp</option>
                    <option>udp</option>
                  </select>
                </Field>
                <Field label="Listen Address (Optional)">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 font-mono text-xs"
                    placeholder="0.0.0.0"
                    value={newFwd.listen_address}
                    onChange={(e) => setNewFwd({ ...newFwd, listen_address: e.target.value })}
                  />
                </Field>
                <Field label="Listen Port">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 font-mono text-xs"
                    type="number"
                    required
                    min="1"
                    max="65535"
                    value={newFwd.listen_port}
                    onChange={(e) => setNewFwd({ ...newFwd, listen_port: e.target.value })}
                  />
                </Field>
                <Field label="Destination Address">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 font-mono text-xs"
                    required
                    placeholder="127.0.0.1 or internal IP"
                    value={newFwd.dest_address}
                    onChange={(e) => setNewFwd({ ...newFwd, dest_address: e.target.value })}
                  />
                </Field>
                <Field label="Destination Port">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 font-mono text-xs"
                    type="number"
                    required
                    min="1"
                    max="65535"
                    value={newFwd.dest_port}
                    onChange={(e) => setNewFwd({ ...newFwd, dest_port: e.target.value })}
                  />
                </Field>
                <Field label="Description">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
                    value={newFwd.description}
                    onChange={(e) => setNewFwd({ ...newFwd, description: e.target.value })}
                  />
                </Field>
              </div>
              <div className="flex gap-2 justify-end pt-3 border-t border-slate-100">
                <button
                  type="button"
                  className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all"
                  onClick={() => setShowCreateForward(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
                >
                  Create Forward
                </button>
              </div>
            </form>
          </Modal>
        </div>
      )}

      {/* ─── ZONES TAB ─── */}
      {tab === 'zones' && (
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-5">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between pb-4 border-b border-slate-100">
              <div>
                <h2 className="text-base font-semibold text-slate-900">Network Security Zones ({zones.length})</h2>
                <p className="text-xs text-slate-500">Group physical and virtual network interfaces into isolated trust domains.</p>
              </div>
              <button
                type="button"
                className="rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
                onClick={() => setShowCreateZone(true)}
              >
                + Add Zone
              </button>
            </div>

            {zones.length === 0 && !loading ? (
              <div className="py-12 text-center">
                <span className="text-4xl mb-2 block">🌐</span>
                <h3 className="text-sm font-semibold text-slate-900">No network zones defined</h3>
                <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">Group network adapters into internal, DMZ, or external perimeter zones.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 text-xs font-semibold text-slate-500 uppercase tracking-wider">
                      <th className="pb-3 pr-4">Zone Name</th>
                      <th className="pb-3 pr-4">Kind</th>
                      <th className="pb-3 pr-4">Interfaces</th>
                      <th className="pb-3 pr-4">Created At</th>
                      <th className="pb-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {zones.map((z) => (
                      <tr key={z.id} className="hover:bg-slate-50/60 transition-colors">
                        <td className="py-3 pr-4 font-semibold text-slate-800">{z.name}</td>
                        <td className="py-3 pr-4">
                          <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                            z.kind === 'internal'
                              ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                              : z.kind === 'dmz'
                              ? 'bg-amber-50 text-amber-700 border border-amber-200'
                              : 'bg-purple-50 text-purple-700 border border-purple-200'
                          }`}>
                            {z.kind}
                          </span>
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs text-slate-600">{z.interfaces || '-'}</td>
                        <td className="py-3 pr-4 text-xs text-slate-500">{formatTs(z.created_at)}</td>
                        <td className="py-3 text-right">
                          <button
                            type="button"
                            className="rounded-lg bg-red-600 px-3 py-1 text-xs font-medium text-white hover:bg-red-700 transition-all"
                            onClick={withStepUp(async () => {
                              await networkApi.deleteZone(serverId, z.id);
                              goeyToast.success('Network zone deleted');
                              loadData();
                            })}
                          >
                            Delete
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <Modal
            isOpen={showCreateZone}
            onClose={() => setShowCreateZone(false)}
            title="New Network Zone"
          >
            <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); void handleCreateZone(); }}>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Zone Name">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
                    required
                    value={newZone.name}
                    onChange={(e) => setNewZone({ ...newZone, name: e.target.value })}
                  />
                </Field>
                <Field label="Kind">
                  <select
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
                    value={newZone.kind}
                    onChange={(e) => setNewZone({ ...newZone, kind: e.target.value })}
                  >
                    {['internal', 'dmz', 'external'].map((k) => <option key={k}>{k}</option>)}
                  </select>
                </Field>
                <Field label="Interfaces">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 font-mono text-xs"
                    placeholder="eth0 eth1"
                    value={newZone.interfaces}
                    onChange={(e) => setNewZone({ ...newZone, interfaces: e.target.value })}
                  />
                </Field>
              </div>
              <div className="flex gap-2 justify-end pt-3 border-t border-slate-100">
                <button
                  type="button"
                  className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all"
                  onClick={() => setShowCreateZone(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
                >
                  Create Zone
                </button>
              </div>
            </form>
          </Modal>
        </div>
      )}

      {/* ─── WIREGUARD PEERS (CARD LIST) ─── */}
      {tab === 'wireguard' && (
        <div className="space-y-6">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-base font-semibold text-slate-900">WireGuard VPN Peers ({peers.length})</h2>
              <p className="text-xs text-slate-500">Cryptographic mesh connections for point-to-point server and client tunnels.</p>
            </div>
            <button
              type="button"
              className="rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
              onClick={() => setShowCreatePeer(true)}
            >
              + Add Peer
            </button>
          </div>

          {peers.length === 0 && !loading ? (
            <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
              <span className="text-4xl mb-3 block">🔒</span>
              <h3 className="text-base font-semibold text-slate-900">No WireGuard peers configured</h3>
              <p className="text-sm text-slate-500 mt-1 max-w-md mx-auto">
                Add public keys and endpoint tunnels to interconnect with other nodes securely.
              </p>
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {peers.map((p) => (
                <div key={p.id} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4 hover:border-slate-300 transition-all flex flex-col justify-between">
                  <div className="space-y-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-lg">🔐</span>
                        <div>
                          <h3 className="text-sm font-semibold text-slate-900">{p.label || 'Unnamed Peer'}</h3>
                          <span className={`inline-block rounded-full px-2 py-0.5 text-[11px] font-medium mt-0.5 ${
                            p.enabled
                              ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                              : 'bg-slate-100 text-slate-600'
                          }`}>
                            {p.enabled ? 'Enabled' : 'Disabled'}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="space-y-2 text-xs pt-1">
                      <div>
                        <span className="text-slate-400 font-medium">Public Key</span>
                        <p className="font-mono text-slate-700 bg-slate-50 rounded px-2 py-1 mt-0.5 select-all border border-slate-100" title={p.public_key}>
                          {truncateKey(p.public_key, 10, 10)}
                        </p>
                      </div>

                      <div className="flex justify-between py-1 border-b border-slate-100">
                        <span className="text-slate-500">Allowed IPs</span>
                        <span className="font-mono text-slate-800 font-medium">{p.allowed_ips || '-'}</span>
                      </div>

                      <div className="flex justify-between py-1 border-b border-slate-100">
                        <span className="text-slate-500">Endpoint</span>
                        <span className="font-mono text-slate-800 font-medium">{p.endpoint || 'Dynamic / None'}</span>
                      </div>

                      <div className="flex justify-between py-1">
                        <span className="text-slate-500">Keepalive</span>
                        <span className="font-mono text-slate-800">{p.persistent_keepalive ? `${p.persistent_keepalive}s` : 'Off'}</span>
                      </div>
                    </div>
                  </div>

                  <div className="pt-3 border-t border-slate-100 flex justify-end">
                    <button
                      type="button"
                      className="rounded-lg bg-red-600 px-3 py-1 text-xs font-medium text-white hover:bg-red-700 transition-all"
                      onClick={withStepUp(async () => {
                        await networkApi.deletePeer(serverId, p.id);
                        goeyToast.success('WireGuard peer deleted');
                        loadData();
                      })}
                    >
                      Delete Peer
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          <Modal
            isOpen={showCreatePeer}
            onClose={() => setShowCreatePeer(false)}
            title="New WireGuard Peer"
          >
            <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); void handleCreatePeer(); }}>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="sm:col-span-2">
                  <Field label="Public Key">
                    <input
                      className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 font-mono text-xs"
                      required
                      placeholder="e.g. 4s7D...="
                      value={newPeer.public_key}
                      onChange={(e) => setNewPeer({ ...newPeer, public_key: e.target.value })}
                    />
                  </Field>
                </div>
                <Field label="Label / Friendly Name">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
                    placeholder="e.g. edge-router-singapore"
                    value={newPeer.label}
                    onChange={(e) => setNewPeer({ ...newPeer, label: e.target.value })}
                  />
                </Field>
                <Field label="Allowed IPs">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 font-mono text-xs"
                    placeholder="10.0.0.2/32"
                    value={newPeer.allowed_ips}
                    onChange={(e) => setNewPeer({ ...newPeer, allowed_ips: e.target.value })}
                  />
                </Field>
                <Field label="Endpoint (Host:Port)">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 font-mono text-xs"
                    placeholder="vpn.example.com:51820"
                    value={newPeer.endpoint}
                    onChange={(e) => setNewPeer({ ...newPeer, endpoint: e.target.value })}
                  />
                </Field>
                <Field label="Persistent Keepalive (seconds)">
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 font-mono text-xs"
                    type="number"
                    min="0"
                    value={newPeer.persistent_keepalive}
                    onChange={(e) => setNewPeer({ ...newPeer, persistent_keepalive: e.target.value })}
                  />
                </Field>
                <div className="flex items-center gap-2 pt-6">
                  <input
                    id="peer-enabled"
                    type="checkbox"
                    className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 h-4 w-4"
                    checked={newPeer.enabled}
                    onChange={(e) => setNewPeer({ ...newPeer, enabled: e.target.checked })}
                  />
                  <label htmlFor="peer-enabled" className="text-sm font-medium text-slate-700">Enabled</label>
                </div>
              </div>
              <div className="flex gap-2 justify-end pt-3 border-t border-slate-100">
                <button
                  type="button"
                  className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all"
                  onClick={() => setShowCreatePeer(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
                >
                  Save Peer
                </button>
              </div>
            </form>
          </Modal>
        </div>
      )}

      {/* ─── DIAGNOSTICS TAB ─── */}
      {tab === 'diag' && (
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
            <div>
              <h2 className="text-base font-semibold text-slate-900">Network Diagnostics</h2>
              <p className="text-xs text-slate-500">Run ping and traceroute tests directly from the remote server node.</p>
            </div>

            <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); void runDiag(); }}>
              <div className="grid gap-3 sm:grid-cols-3">
                <div className="sm:col-span-2">
                  <Field label="Target (IP or Hostname)">
                    <input
                      className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 font-mono text-xs"
                      required
                      placeholder="e.g. 1.1.1.1 or google.com"
                      value={diagTarget}
                      onChange={(e) => setDiagTarget(e.target.value)}
                    />
                  </Field>
                </div>
                <Field label="Tool Mode">
                  <select
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
                    value={diagMode}
                    onChange={(e) => setDiagMode(e.target.value as 'ping' | 'trace')}
                  >
                    <option value="ping">Ping (ICMP Echo)</option>
                    <option value="trace">Traceroute (Hop Path)</option>
                  </select>
                </Field>
              </div>
              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={diagRunning}
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all disabled:opacity-50"
                >
                  {diagRunning ? 'Running Probe…' : 'Run Diagnostic Probe'}
                </button>
              </div>
            </form>

            {diagResult && (
              <div className="rounded-lg border border-slate-200 bg-slate-900 p-4 font-mono text-xs text-slate-100 space-y-2">
                <div className="flex items-center justify-between pb-2 border-b border-slate-800 text-slate-400">
                  <span className="flex items-center gap-2">
                    <span className={`h-2 w-2 rounded-full ${diagResult.success ? 'bg-emerald-400' : 'bg-red-400'}`} />
                    {diagResult.mode.toUpperCase()} → {diagResult.target}
                  </span>
                  <span>{formatTs(diagResult.observed_at)}</span>
                </div>
                <pre className="overflow-x-auto whitespace-pre">{diagResult.output}</pre>
              </div>
            )}
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-4 border-b border-slate-100">
              <div>
                <h2 className="text-base font-semibold text-slate-900">Listening Socket Inventory</h2>
                <p className="text-xs text-slate-500">Live active daemon sockets listening on host interfaces.</p>
              </div>
              <button
                type="button"
                className="rounded-lg border border-slate-200 bg-white px-3.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-all"
                onClick={() => { void loadPorts(); }}
              >
                {portsLoading ? 'Probing Sockets…' : 'Inspect Listening Sockets'}
              </button>
            </div>

            {ports.length === 0 ? (
              <div className="py-8 text-center text-sm text-slate-400">
                Click "Inspect Listening Sockets" to query open ports.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 text-xs font-semibold text-slate-500 uppercase tracking-wider">
                      <th className="pb-3 pr-4">Protocol</th>
                      <th className="pb-3 pr-4">Listen Address</th>
                      <th className="pb-3 pr-4">Port</th>
                      <th className="pb-3">Bound Process</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {ports.map((p, i) => (
                      <tr key={i} className="hover:bg-slate-50/60 transition-colors">
                        <td className="py-2.5 pr-4">
                          <span className="rounded-full px-2 py-0.5 text-xs font-medium bg-slate-100 text-slate-700 uppercase">
                            {p.protocol}
                          </span>
                        </td>
                        <td className="py-2.5 pr-4 font-mono text-xs text-slate-700">{p.local_address}</td>
                        <td className="py-2.5 pr-4 font-mono text-xs font-semibold text-indigo-600">{p.local_port}</td>
                        <td className="py-2.5 text-xs text-slate-600 font-mono">{p.process_name || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ─── APPLY LOG TAB ─── */}
      {tab === 'applylog' && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900">Firewall Apply Audit Log ({applyLog.length})</h2>
            <p className="text-xs text-slate-500">History of firewall sync transactions executed on this server.</p>
          </div>

          {applyLog.length === 0 && !loading ? (
            <div className="py-12 text-center">
              <span className="text-4xl mb-2 block">📋</span>
              <h3 className="text-sm font-semibold text-slate-900">No apply events recorded</h3>
              <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">Transactions will be recorded here when rules are deployed.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-xs font-semibold text-slate-500 uppercase tracking-wider">
                    <th className="pb-3 pr-4">Timestamp</th>
                    <th className="pb-3 pr-4">Applied By</th>
                    <th className="pb-3 pr-4">Outcome</th>
                    <th className="pb-3">Details / Error</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {applyLog.map((log) => {
                    const isSuccess = log.outcome.toLowerCase() === 'success' || log.outcome.toLowerCase() === 'applied';
                    return (
                      <tr key={log.id} className="hover:bg-slate-50/60 transition-colors">
                        <td className="py-3 pr-4 text-xs text-slate-500">{formatTs(log.created_at)}</td>
                        <td className="py-3 pr-4 font-mono text-xs text-slate-700">{log.applied_by}</td>
                        <td className="py-3 pr-4">
                          <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                            isSuccess
                              ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                              : 'bg-red-50 text-red-700 border border-red-200'
                          }`}>
                            {log.outcome}
                          </span>
                        </td>
                        <td className="py-3 text-xs text-slate-500 font-mono">{log.error_message || '-'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
