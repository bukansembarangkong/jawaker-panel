import { useCallback, useEffect, useState } from 'react';

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
  EmptyState,
  ErrorNote,
  Field,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
} from '../components/ui';

type Tab = 'firewall' | 'forwards' | 'zones' | 'wireguard' | 'diag' | 'applylog';

function formatTs(v: string | null | undefined): string {
  if (!v) return '—';
  try { return new Date(v).toLocaleString(); } catch { return v; }
}

function toError(e: unknown): Error {
  return e instanceof Error ? e : new Error(String(e));
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
    return () => fn().catch((e: unknown) => {
      if (isStepUpRequired(e)) {
        setStepUpAction(() => fn);
        setStepUpPending(true);
      } else {
        setError(toError(e));
      }
    });
  }

  // ─── Firewall actions ─────────────────────────────────────────────────────
  async function applyFirewall() {
    await networkApi.applyFirewall(serverId);
    loadData();
  }

  async function doLoadLive() {
    setLiveLoading(true);
    setLiveChains(null);
    try {
      const r = await networkApi.getLiveFirewall(serverId);
      const text = (r.chains ?? []).map((c) =>
        `Table: ${c.table}  Chain: ${c.chain}  Policy: ${c.policy ?? '—'}\n` +
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
    setShowCreateRule(false);
    setNewRule({ chain: 'INPUT', priority: '100', protocol: 'tcp', source_cidr: '', dest_cidr: '', dest_port_min: '', dest_port_max: '', action: 'ACCEPT', enabled: true, description: '' });
    loadData();
  }

  // ─── Port Forwards ────────────────────────────────────────────────────────
  async function handleCreateForward() {
    await networkApi.createForward(serverId, {
      protocol: newFwd.protocol,
      listen_address: newFwd.listen_address || undefined,
      listen_port: parseInt(newFwd.listen_port, 10),
      dest_address: newFwd.dest_address,
      dest_port: parseInt(newFwd.dest_port, 10),
      description: newFwd.description || undefined,
    });
    setShowCreateForward(false);
    setNewFwd({ protocol: 'tcp', listen_address: '', listen_port: '', dest_address: '', dest_port: '', description: '' });
    loadData();
  }

  // ─── Zones ────────────────────────────────────────────────────────────────
  async function handleCreateZone() {
    await networkApi.createZone(serverId, {
      name: newZone.name,
      kind: newZone.kind || undefined,
      interfaces: newZone.interfaces || undefined,
    });
    setShowCreateZone(false);
    setNewZone({ name: '', kind: 'internal', interfaces: '' });
    loadData();
  }

  // ─── WireGuard ────────────────────────────────────────────────────────────
  async function handleCreatePeer() {
    await networkApi.createPeer(serverId, {
      public_key: newPeer.public_key,
      label: newPeer.label || undefined,
      allowed_ips: newPeer.allowed_ips || undefined,
      endpoint: newPeer.endpoint || undefined,
      persistent_keepalive: newPeer.persistent_keepalive ? parseInt(newPeer.persistent_keepalive, 10) : undefined,
      enabled: newPeer.enabled,
    });
    setShowCreatePeer(false);
    setNewPeer({ public_key: '', label: '', allowed_ips: '', endpoint: '', persistent_keepalive: '25', enabled: true });
    loadData();
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

  const tabClass = (t: Tab) =>
    `px-3 py-1.5 text-sm rounded-md ${tab === t ? 'bg-elevated font-medium text-ink' : 'text-ink-secondary hover:text-ink'}`;

  if (!serverId) {
    return <p className="text-sm text-ink-secondary">No servers available.</p>;
  }

  return (
    <section className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h2 className="text-base font-semibold">Networking</h2>
        <select
          className={inputClass}
          value={serverId}
          onChange={(e) => setServerId(e.target.value)}
          aria-label="Select server"
        >
          {servers.map((s) => (
            <option key={s.id} value={s.id}>{s.name}</option>
          ))}
        </select>
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

      {/* Tabs */}
      <nav aria-label="Networking tabs" className="flex flex-wrap gap-2">
        {(['firewall', 'forwards', 'zones', 'wireguard', 'diag', 'applylog'] as Tab[]).map((t) => (
          <button key={t} type="button" className={tabClass(t)} onClick={() => setTab(t)}>
            {t === 'firewall' ? 'Firewall' :
             t === 'forwards' ? 'Port Forwards' :
             t === 'zones' ? 'Zones' :
             t === 'wireguard' ? 'WireGuard' :
             t === 'diag' ? 'Diagnostics' : 'Apply Log'}
          </button>
        ))}
      </nav>

      {loading && <p className="text-sm text-ink-secondary">Loading…</p>}

      {/* ─── Firewall Tab ─── */}
      {tab === 'firewall' && (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <button type="button" className={primaryButtonClass}
              onClick={withStepUp(applyFirewall)}>Apply to server</button>
            <button type="button" className={secondaryButtonClass}
              onClick={() => { void doLoadLive(); }}>Read live state</button>
            <button type="button" className={secondaryButtonClass}
              onClick={() => setShowCreateRule(true)}>+ Rule</button>
          </div>

          {liveLoading && <p className="text-sm text-ink-secondary">Reading iptables…</p>}
          {liveChains != null && (
            <pre className="overflow-auto rounded-md bg-elevated p-3 text-xs text-ink">{liveChains}</pre>
          )}

          {showCreateRule && (
            <form className="space-y-3 rounded-md border border-line p-4"
              onSubmit={(e) => { e.preventDefault(); void handleCreateRule(); }}>
              <h3 className="text-sm font-medium">New Firewall Rule</h3>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Chain">
                  <select className={inputClass} value={newRule.chain}
                    onChange={(e) => setNewRule({ ...newRule, chain: e.target.value })}>
                    {['INPUT', 'OUTPUT', 'FORWARD'].map((c) => <option key={c}>{c}</option>)}
                  </select>
                </Field>
                <Field label="Priority">
                  <input className={inputClass} value={newRule.priority} type="number"
                    onChange={(e) => setNewRule({ ...newRule, priority: e.target.value })} />
                </Field>
                <Field label="Protocol">
                  <select className={inputClass} value={newRule.protocol}
                    onChange={(e) => setNewRule({ ...newRule, protocol: e.target.value })}>
                    {['tcp', 'udp', 'icmp', 'all'].map((p) => <option key={p}>{p}</option>)}
                  </select>
                </Field>
                <Field label="Action">
                  <select className={inputClass} value={newRule.action}
                    onChange={(e) => setNewRule({ ...newRule, action: e.target.value })}>
                    {['ACCEPT', 'DROP', 'REJECT'].map((a) => <option key={a}>{a}</option>)}
                  </select>
                </Field>
                <Field label="Source CIDR">
                  <input className={inputClass} placeholder="0.0.0.0/0" value={newRule.source_cidr}
                    onChange={(e) => setNewRule({ ...newRule, source_cidr: e.target.value })} />
                </Field>
                <Field label="Dest CIDR">
                  <input className={inputClass} placeholder="0.0.0.0/0" value={newRule.dest_cidr}
                    onChange={(e) => setNewRule({ ...newRule, dest_cidr: e.target.value })} />
                </Field>
                <Field label="Dest port min">
                  <input className={inputClass} type="number" min="1" max="65535" value={newRule.dest_port_min}
                    onChange={(e) => setNewRule({ ...newRule, dest_port_min: e.target.value })} />
                </Field>
                <Field label="Dest port max">
                  <input className={inputClass} type="number" min="1" max="65535" value={newRule.dest_port_max}
                    onChange={(e) => setNewRule({ ...newRule, dest_port_max: e.target.value })} />
                </Field>
                <Field label="Description">
                  <input className={inputClass} value={newRule.description}
                    onChange={(e) => setNewRule({ ...newRule, description: e.target.value })} />
                </Field>
                <Field label="Enabled">
                  <input type="checkbox" checked={newRule.enabled}
                    onChange={(e) => setNewRule({ ...newRule, enabled: e.target.checked })} />
                </Field>
              </div>
              <div className="flex gap-2">
                <button type="submit" className={primaryButtonClass}>Create</button>
                <button type="button" className={secondaryButtonClass}
                  onClick={() => setShowCreateRule(false)}>Cancel</button>
              </div>
            </form>
          )}

          {rules.length === 0 && !loading ? (
            <EmptyState message="No firewall rules defined." />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-ink-secondary">
                  <th className="py-2 pr-4">Chain</th>
                  <th className="py-2 pr-4">Protocol</th>
                  <th className="py-2 pr-4">Source</th>
                  <th className="py-2 pr-4">Dest port</th>
                  <th className="py-2 pr-4">Action</th>
                  <th className="py-2 pr-4">State</th>
                  <th className="py-2"></th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id} className="border-b border-line">
                    <td className="py-2 pr-4 font-mono text-xs">{rule.chain}</td>
                    <td className="py-2 pr-4">{rule.protocol}</td>
                    <td className="py-2 pr-4 font-mono text-xs">{rule.source_cidr || '—'}</td>
                    <td className="py-2 pr-4 font-mono text-xs">
                      {rule.dest_port_min > 0 ? `${rule.dest_port_min}–${rule.dest_port_max}` : '—'}
                    </td>
                    <td className="py-2 pr-4">{rule.action}</td>
                    <td className="py-2 pr-4">{rule.state}</td>
                    <td className="py-2">
                      <button type="button" className={secondaryButtonClass}
                        onClick={withStepUp(async () => {
                          await networkApi.deleteRule(serverId, rule.id);
                          loadData();
                        })}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ─── Port Forwards Tab ─── */}
      {tab === 'forwards' && (
        <div className="space-y-4">
          <button type="button" className={secondaryButtonClass}
            onClick={() => setShowCreateForward(true)}>+ Forward</button>

          {showCreateForward && (
            <form className="space-y-3 rounded-md border border-line p-4"
              onSubmit={(e) => { e.preventDefault(); void handleCreateForward(); }}>
              <h3 className="text-sm font-medium">New Port Forward</h3>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Protocol">
                  <select className={inputClass} value={newFwd.protocol}
                    onChange={(e) => setNewFwd({ ...newFwd, protocol: e.target.value })}>
                    <option>tcp</option><option>udp</option>
                  </select>
                </Field>
                <Field label="Listen address (optional)">
                  <input className={inputClass} placeholder="0.0.0.0" value={newFwd.listen_address}
                    onChange={(e) => setNewFwd({ ...newFwd, listen_address: e.target.value })} />
                </Field>
                <Field label="Listen port" required>
                  <input className={inputClass} type="number" required min="1" max="65535"
                    value={newFwd.listen_port}
                    onChange={(e) => setNewFwd({ ...newFwd, listen_port: e.target.value })} />
                </Field>
                <Field label="Dest address" required>
                  <input className={inputClass} required value={newFwd.dest_address}
                    onChange={(e) => setNewFwd({ ...newFwd, dest_address: e.target.value })} />
                </Field>
                <Field label="Dest port" required>
                  <input className={inputClass} type="number" required min="1" max="65535"
                    value={newFwd.dest_port}
                    onChange={(e) => setNewFwd({ ...newFwd, dest_port: e.target.value })} />
                </Field>
                <Field label="Description">
                  <input className={inputClass} value={newFwd.description}
                    onChange={(e) => setNewFwd({ ...newFwd, description: e.target.value })} />
                </Field>
              </div>
              <div className="flex gap-2">
                <button type="submit" className={primaryButtonClass}>Create</button>
                <button type="button" className={secondaryButtonClass}
                  onClick={() => setShowCreateForward(false)}>Cancel</button>
              </div>
            </form>
          )}

          {forwards.length === 0 && !loading ? (
            <EmptyState message="No port forwards configured." />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-ink-secondary">
                  <th className="py-2 pr-4">Protocol</th>
                  <th className="py-2 pr-4">Listen</th>
                  <th className="py-2 pr-4">Destination</th>
                  <th className="py-2 pr-4">State</th>
                  <th className="py-2"></th>
                </tr>
              </thead>
              <tbody>
                {forwards.map((f) => (
                  <tr key={f.id} className="border-b border-line">
                    <td className="py-2 pr-4">{f.protocol}</td>
                    <td className="py-2 pr-4 font-mono text-xs">
                      {f.listen_address ? `${f.listen_address}:` : ''}{f.listen_port}
                    </td>
                    <td className="py-2 pr-4 font-mono text-xs">{f.dest_address}:{f.dest_port}</td>
                    <td className="py-2 pr-4">{f.state}</td>
                    <td className="py-2">
                      <button type="button" className={secondaryButtonClass}
                        onClick={withStepUp(async () => {
                          await networkApi.deleteForward(serverId, f.id);
                          loadData();
                        })}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ─── Zones Tab ─── */}
      {tab === 'zones' && (
        <div className="space-y-4">
          <button type="button" className={secondaryButtonClass}
            onClick={() => setShowCreateZone(true)}>+ Zone</button>

          {showCreateZone && (
            <form className="space-y-3 rounded-md border border-line p-4"
              onSubmit={(e) => { e.preventDefault(); void handleCreateZone(); }}>
              <h3 className="text-sm font-medium">New Network Zone</h3>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Name" required>
                  <input className={inputClass} required value={newZone.name}
                    onChange={(e) => setNewZone({ ...newZone, name: e.target.value })} />
                </Field>
                <Field label="Kind">
                  <select className={inputClass} value={newZone.kind}
                    onChange={(e) => setNewZone({ ...newZone, kind: e.target.value })}>
                    {['internal', 'dmz', 'external'].map((k) => <option key={k}>{k}</option>)}
                  </select>
                </Field>
                <Field label="Interfaces">
                  <input className={inputClass} placeholder="eth0 eth1" value={newZone.interfaces}
                    onChange={(e) => setNewZone({ ...newZone, interfaces: e.target.value })} />
                </Field>
              </div>
              <div className="flex gap-2">
                <button type="submit" className={primaryButtonClass}>Create</button>
                <button type="button" className={secondaryButtonClass}
                  onClick={() => setShowCreateZone(false)}>Cancel</button>
              </div>
            </form>
          )}

          {zones.length === 0 && !loading ? (
            <EmptyState message="No network zones defined." />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-ink-secondary">
                  <th className="py-2 pr-4">Name</th>
                  <th className="py-2 pr-4">Kind</th>
                  <th className="py-2 pr-4">Interfaces</th>
                  <th className="py-2 pr-4">Created</th>
                  <th className="py-2"></th>
                </tr>
              </thead>
              <tbody>
                {zones.map((z) => (
                  <tr key={z.id} className="border-b border-line">
                    <td className="py-2 pr-4">{z.name}</td>
                    <td className="py-2 pr-4">{z.kind}</td>
                    <td className="py-2 pr-4 font-mono text-xs">{z.interfaces || '—'}</td>
                    <td className="py-2 pr-4 text-xs text-ink-secondary">{formatTs(z.created_at)}</td>
                    <td className="py-2">
                      <button type="button" className={secondaryButtonClass}
                        onClick={withStepUp(async () => {
                          await networkApi.deleteZone(serverId, z.id);
                          loadData();
                        })}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ─── WireGuard Tab ─── */}
      {tab === 'wireguard' && (
        <div className="space-y-4">
          <button type="button" className={secondaryButtonClass}
            onClick={() => setShowCreatePeer(true)}>+ Peer</button>

          {showCreatePeer && (
            <form className="space-y-3 rounded-md border border-line p-4"
              onSubmit={(e) => { e.preventDefault(); void handleCreatePeer(); }}>
              <h3 className="text-sm font-medium">New WireGuard Peer</h3>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Public key" required>
                  <input className={inputClass} required value={newPeer.public_key}
                    onChange={(e) => setNewPeer({ ...newPeer, public_key: e.target.value })} />
                </Field>
                <Field label="Label">
                  <input className={inputClass} value={newPeer.label}
                    onChange={(e) => setNewPeer({ ...newPeer, label: e.target.value })} />
                </Field>
                <Field label="Allowed IPs">
                  <input className={inputClass} placeholder="10.0.0.2/32" value={newPeer.allowed_ips}
                    onChange={(e) => setNewPeer({ ...newPeer, allowed_ips: e.target.value })} />
                </Field>
                <Field label="Endpoint">
                  <input className={inputClass} placeholder="host:port" value={newPeer.endpoint}
                    onChange={(e) => setNewPeer({ ...newPeer, endpoint: e.target.value })} />
                </Field>
                <Field label="Persistent keepalive (s)">
                  <input className={inputClass} type="number" min="0" value={newPeer.persistent_keepalive}
                    onChange={(e) => setNewPeer({ ...newPeer, persistent_keepalive: e.target.value })} />
                </Field>
                <Field label="Enabled">
                  <input type="checkbox" checked={newPeer.enabled}
                    onChange={(e) => setNewPeer({ ...newPeer, enabled: e.target.checked })} />
                </Field>
              </div>
              <div className="flex gap-2">
                <button type="submit" className={primaryButtonClass}>Create</button>
                <button type="button" className={secondaryButtonClass}
                  onClick={() => setShowCreatePeer(false)}>Cancel</button>
              </div>
            </form>
          )}

          {peers.length === 0 && !loading ? (
            <EmptyState message="No WireGuard peers configured." />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-ink-secondary">
                  <th className="py-2 pr-4">Label</th>
                  <th className="py-2 pr-4">Public key</th>
                  <th className="py-2 pr-4">Allowed IPs</th>
                  <th className="py-2 pr-4">Endpoint</th>
                  <th className="py-2 pr-4">Enabled</th>
                  <th className="py-2"></th>
                </tr>
              </thead>
              <tbody>
                {peers.map((p) => (
                  <tr key={p.id} className="border-b border-line">
                    <td className="py-2 pr-4">{p.label || '—'}</td>
                    <td className="py-2 pr-4 font-mono text-xs max-w-[10rem] truncate">{p.public_key}</td>
                    <td className="py-2 pr-4 font-mono text-xs">{p.allowed_ips || '—'}</td>
                    <td className="py-2 pr-4 font-mono text-xs">{p.endpoint || '—'}</td>
                    <td className="py-2 pr-4">{p.enabled ? 'Yes' : 'No'}</td>
                    <td className="py-2">
                      <button type="button" className={secondaryButtonClass}
                        onClick={withStepUp(async () => {
                          await networkApi.deletePeer(serverId, p.id);
                          loadData();
                        })}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ─── Diagnostics Tab ─── */}
      {tab === 'diag' && (
        <div className="space-y-6">
          <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); void runDiag(); }}>
            <h3 className="text-sm font-medium">Network Diagnostics</h3>
            <div className="flex flex-wrap gap-3">
              <div className="flex-1">
                <Field label="Target (IP or hostname)">
                  <input className={inputClass} required value={diagTarget}
                    placeholder="8.8.8.8"
                    onChange={(e) => setDiagTarget(e.target.value)} />
                </Field>
              </div>
              <Field label="Mode">
                <select className={inputClass} value={diagMode}
                  onChange={(e) => setDiagMode(e.target.value as 'ping' | 'trace')}>
                  <option value="ping">Ping</option>
                  <option value="trace">Traceroute</option>
                </select>
              </Field>
            </div>
            <button type="submit" disabled={diagRunning} className={primaryButtonClass}>
              {diagRunning ? 'Running…' : 'Run'}
            </button>
          </form>

          {diagResult && (
            <div className="space-y-1">
              <p className="text-xs text-ink-secondary">
                {diagResult.mode} → {diagResult.target} — {diagResult.success ? 'success' : 'failed'} — {formatTs(diagResult.observed_at)}
              </p>
              <pre className="overflow-auto rounded-md bg-elevated p-3 text-xs text-ink">{diagResult.output}</pre>
            </div>
          )}

          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <h3 className="text-sm font-medium">Listening Ports</h3>
              <button type="button" className={secondaryButtonClass}
                onClick={() => { void loadPorts(); }}>
                {portsLoading ? 'Loading…' : 'Refresh'}
              </button>
            </div>
            {ports.length > 0 && (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line text-left text-ink-secondary">
                    <th className="py-2 pr-4">Protocol</th>
                    <th className="py-2 pr-4">Address</th>
                    <th className="py-2 pr-4">Port</th>
                    <th className="py-2 pr-4">Process</th>
                  </tr>
                </thead>
                <tbody>
                  {ports.map((p, i) => (
                    <tr key={i} className="border-b border-line">
                      <td className="py-2 pr-4">{p.protocol}</td>
                      <td className="py-2 pr-4 font-mono text-xs">{p.local_address}</td>
                      <td className="py-2 pr-4 font-mono text-xs">{p.local_port}</td>
                      <td className="py-2 pr-4 text-xs">{p.process_name ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ─── Apply Log Tab ─── */}
      {tab === 'applylog' && (
        <div className="space-y-4">
          {applyLog.length === 0 && !loading ? (
            <EmptyState message="No apply events recorded." />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-ink-secondary">
                  <th className="py-2 pr-4">When</th>
                  <th className="py-2 pr-4">Applied by</th>
                  <th className="py-2 pr-4">Outcome</th>
                  <th className="py-2">Error</th>
                </tr>
              </thead>
              <tbody>
                {applyLog.map((log) => (
                  <tr key={log.id} className="border-b border-line">
                    <td className="py-2 pr-4 text-xs text-ink-secondary">{formatTs(log.created_at)}</td>
                    <td className="py-2 pr-4 font-mono text-xs">{log.applied_by}</td>
                    <td className="py-2 pr-4">{log.outcome}</td>
                    <td className="py-2 text-xs text-ink-secondary">{log.error_message || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </section>
  );
}
