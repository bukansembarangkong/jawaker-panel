import { useCallback, useEffect, useState } from 'react';
import { goeyToast } from 'goey-toast';

import {
  securityCenterApi,
  attackModeApi,
  isStepUpRequired,
  type AttackModeStatus,
  type BanEntry,
  type HardeningCheck,
  type HardeningFinding,
  type LiveBan,
  type SecurityEvent,
  type SSHPosture,
  type WAFRule,
} from '../api/client';
import { StepUpPrompt } from '../components/StepUpPrompt';
import {
  ErrorNote,
  Field,
  Modal,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
} from '../components/ui';

type Tab = 'hardening' | 'ssh' | 'events' | 'bans' | 'waf';

function formatTs(v: string | null | undefined): string {
  if (!v) return '-';
  try { return new Date(v).toLocaleString(); } catch { return v; }
}

function toError(e: unknown): Error {
  return e instanceof Error ? e : new Error(String(e));
}

function severityClass(s: string): string {
  switch (s) {
    case 'critical': return 'text-red-600 font-semibold';
    case 'high':     return 'text-orange-600 font-semibold';
    case 'medium':   return 'text-yellow-600';
    case 'low':      return 'text-blue-600';
    default:         return 'text-slate-500';
  }
}

function statusIcon(s: string): string {
  switch (s) {
    case 'pass': return '✓';
    case 'fail': return '✗';
    case 'warn': return '⚠';
    default:     return '-';
  }
}

function wafActionBadge(action: string) {
  const cls =
    action === 'block'     ? 'bg-red-100 text-red-700' :
    action === 'allow'     ? 'bg-emerald-100 text-emerald-700' :
    action === 'challenge' ? 'bg-amber-100 text-amber-700' :
                             'bg-slate-100 text-slate-600';
  return (
    <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${cls}`}>
      {action.toUpperCase()}
    </span>
  );
}

function eventKindIcon(kind: string): string {
  if (kind.includes('ssh') || kind.includes('auth')) return '🔑';
  if (kind.includes('ban') || kind.includes('block')) return '🚫';
  if (kind.includes('scan') || kind.includes('probe')) return '🔍';
  if (kind.includes('ddos') || kind.includes('flood')) return '🌊';
  return '⚠️';
}

interface ServerOption { id: string; name: string; }

const thClass = 'px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50';
const tdClass = 'px-4 py-3 text-sm text-slate-800';

export function SecurityCenterPage() {
  const [servers, setServers] = useState<ServerOption[]>([]);
  const [serverId, setServerId] = useState('');
  const [tab, setTab] = useState<Tab>('hardening');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [stepUpPending, setStepUpPending] = useState(false);
  const [stepUpAction, setStepUpAction] = useState<(() => Promise<void>) | null>(null);
  const [attackMode, setAttackMode] = useState<AttackModeStatus | null>(null);
  const [attackModeLoading, setAttackModeLoading] = useState(false);

  // Hardening tab
  const [checks, setChecks] = useState<HardeningCheck[]>([]);
  const [findings, setFindings] = useState<HardeningFinding[] | null>(null);
  const [scanRunning, setScanRunning] = useState(false);

  // SSH tab
  const [posture, setPosture] = useState<SSHPosture | null>(null);
  const [postureLoading, setPostureLoading] = useState(false);

  // Events tab
  const [events, setEvents] = useState<SecurityEvent[]>([]);

  // Bans tab
  const [bans, setBans] = useState<BanEntry[]>([]);
  const [liveBans, setLiveBans] = useState<LiveBan[] | null>(null);
  const [liveLoading, setLiveLoading] = useState(false);
  const [showCreateBan, setShowCreateBan] = useState(false);
  const [newBan, setNewBan] = useState({ ip: '', reason: '', source: 'manual' });

  // WAF tab
  const [wafRules, setWafRules] = useState<WAFRule[]>([]);
  const [showCreateWAF, setShowCreateWAF] = useState(false);
  const [newWAF, setNewWAF] = useState({
    kind: 'rate_limit', pattern: '', action: 'block',
    enabled: true, priority: '100', description: '',
  });

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
      securityCenterApi.listChecks(serverId),
      securityCenterApi.listEvents(serverId),
      securityCenterApi.listBans(serverId),
      securityCenterApi.listWAFRules(serverId),
    ]).then(([c, ev, b, w]) => {
      setChecks(c.checks ?? []);
      setEvents(ev.events ?? []);
      setBans(b.bans ?? []);
      setWafRules(w.rules ?? []);
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

  async function runScan() {
    setScanRunning(true);
    setFindings(null);
    try {
      const r = await securityCenterApi.triggerScan(serverId);
      setFindings(r.findings ?? []);
      goeyToast.success('Hardening scan completed');
      loadData();
    } catch (e) {
      setError(toError(e));
    } finally {
      setScanRunning(false);
    }
  }

  async function loadSSHPosture() {
    setPostureLoading(true);
    try {
      const r = await securityCenterApi.getSSHPosture(serverId);
      setPosture(r.posture);
    } catch (e) {
      setError(toError(e));
    } finally {
      setPostureLoading(false);
    }
  }

  async function loadLiveBans() {
    setLiveLoading(true);
    try {
      const r = await securityCenterApi.getLiveBans(serverId);
      setLiveBans(r.bans ?? []);
    } catch (e) {
      setError(toError(e));
    } finally {
      setLiveLoading(false);
    }
  }

  async function handleCreateBan() {
    try {
      await securityCenterApi.createBan(serverId, {
        ip: newBan.ip, reason: newBan.reason || undefined, source: newBan.source || undefined,
      });
      goeyToast.success('IP ban created');
      setShowCreateBan(false);
      setNewBan({ ip: '', reason: '', source: 'manual' });
      loadData();
    } catch (err) {
      const e = toError(err);
      goeyToast.error(`Failed: ${e.message}`);
      setError(e);
    }
  }

  async function handleCreateWAF() {
    try {
      await securityCenterApi.createWAFRule(serverId, {
        kind: newWAF.kind, pattern: newWAF.pattern, action: newWAF.action,
        enabled: newWAF.enabled, priority: parseInt(newWAF.priority, 10) || 100,
        description: newWAF.description || undefined,
      });
      goeyToast.success('WAF rule created');
      setShowCreateWAF(false);
      setNewWAF({ kind: 'rate_limit', pattern: '', action: 'block', enabled: true, priority: '100', description: '' });
      loadData();
    } catch (err) {
      const e = toError(err);
      goeyToast.error(`Failed: ${e.message}`);
      setError(e);
    }
  }

  async function loadAttackMode(sid: string) {
    if (!sid) return;
    try {
      const res = await attackModeApi.get(sid);
      setAttackMode(res.attack_mode);
    } catch { /* ignore */ }
  }

  async function handleToggleAttackMode() {
    if (!serverId) return;
    setAttackModeLoading(true);
    try {
      if (attackMode?.enabled) {
        await attackModeApi.disable(serverId);
        goeyToast.success('Under Attack Mode deactivated');
      } else {
        await attackModeApi.enable(serverId);
        goeyToast.success('Under Attack Mode activated');
      }
      await loadAttackMode(serverId);
    } catch (err) {
      const e = toError(err);
      goeyToast.error(`Failed: ${e.message}`);
      setError(e);
    } finally {
      setAttackModeLoading(false);
    }
  }

  const tabClass = (t: Tab) =>
    `px-4 py-2 text-sm font-medium transition-colors ${
      tab === t
        ? 'border-b-2 border-indigo-600 text-indigo-600'
        : 'text-slate-500 hover:text-slate-700'
    }`;

  if (!serverId) return <p className="text-sm text-slate-500">No servers available.</p>;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Security Center</h1>
          <p className="text-sm text-slate-500">WAF rules, IP bans, hardening checks, and security events.</p>
        </div>
        <select
          className={inputClass}
          value={serverId}
          onChange={(e) => { setServerId(e.target.value); void loadAttackMode(e.target.value); }}
          aria-label="Select server"
        >
          {servers.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
      </div>

      <div className={`rounded-xl border-2 p-5 flex items-start justify-between gap-4 ${
        attackMode?.enabled
          ? 'border-red-400 bg-red-50'
          : 'border-slate-200 bg-white shadow-sm'
      }`}>
        <div>
          <p className={`text-sm font-semibold ${attackMode?.enabled ? 'text-red-700' : 'text-slate-900'}`}>
            {attackMode?.enabled ? '🚨 Under Attack Mode — ACTIVE' : '🛡️ Under Attack Mode'}
          </p>
          <p className="text-xs text-slate-500 mt-1">
            {attackMode?.enabled
              ? `Activated: ${attackMode.activated_at ? new Date(attackMode.activated_at).toLocaleString() : 'just now'}. Rate limits tightened ${attackMode.rate_limit_multiplier}×. Suspicious traffic challenged.`
              : 'Temporarily tightens rate limits, challenges suspicious traffic, restricts expensive endpoints.'}
          </p>
        </div>
        <button
          onClick={() => void handleToggleAttackMode()}
          disabled={attackModeLoading}
          className={`shrink-0 rounded-lg px-4 py-2 text-sm font-medium text-white shadow-sm transition-all active:scale-95 disabled:opacity-50 ${
            attackMode?.enabled
              ? 'bg-emerald-600 hover:bg-emerald-700'
              : 'bg-red-600 hover:bg-red-700'
          }`}
        >
          {attackModeLoading ? 'Updating…' : attackMode?.enabled ? 'Deactivate' : 'Activate Under Attack Mode'}
        </button>
      </div>

      {error && <ErrorNote error={error} onRetry={loadData} />}

      {stepUpPending && (
        <StepUpPrompt
          onElevated={() => { setStepUpPending(false); if (stepUpAction) void stepUpAction(); }}
          onCancel={() => { setStepUpPending(false); setStepUpAction(null); }}
        />
      )}

      <div className="flex gap-1 border-b border-slate-200">
        {(['hardening', 'ssh', 'events', 'bans', 'waf'] as Tab[]).map((t) => (
          <button key={t} type="button" className={tabClass(t)} onClick={() => setTab(t)}>
            {t === 'hardening' ? 'Hardening' :
             t === 'ssh' ? 'SSH Posture' :
             t === 'events' ? 'Events' :
             t === 'bans' ? 'Bans' : 'WAF Rules'}
          </button>
        ))}
      </div>

      {loading && <p className="text-sm text-slate-500">Loading…</p>}

      {tab === 'hardening' && (
        <div className="space-y-5">
          <button type="button" className={primaryButtonClass}
            onClick={() => { void runScan(); }}
            disabled={scanRunning}>
            {scanRunning ? 'Scanning…' : 'Run Scan'}
          </button>

          {findings != null && (
            <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-100">
                <h3 className="text-sm font-semibold text-slate-900">Scan results ({findings.length} findings)</h3>
              </div>
              {findings.length === 0 ? (
                <div className="flex flex-col items-center py-12 gap-2 text-center">
                  <span className="text-3xl">✅</span>
                  <p className="font-medium text-slate-700">All checks passed</p>
                  <p className="text-sm text-slate-500">No findings.</p>
                </div>
              ) : (
                <table className="w-full">
                  <thead>
                    <tr>
                      <th className={thClass}>Status</th>
                      <th className={thClass}>Severity</th>
                      <th className={thClass}>Check</th>
                      <th className={thClass}>Title</th>
                      <th className={thClass}>Remediation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {findings.map((f, i) => (
                      <tr key={i}>
                        <td className={tdClass}>{statusIcon(f.status)}</td>
                        <td className={`${tdClass} ${severityClass(f.severity)}`}>{f.severity}</td>
                        <td className="px-4 py-3 font-mono text-xs text-slate-700">{f.check_name}</td>
                        <td className={tdClass}>{f.title}</td>
                        <td className="px-4 py-3 text-xs text-slate-500">{f.remediation || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-100">
              <h3 className="text-sm font-semibold text-slate-900">Stored checks</h3>
            </div>
            {checks.length === 0 && !loading ? (
              <div className="flex flex-col items-center py-12 gap-2 text-center">
                <span className="text-3xl">🔒</span>
                <p className="font-medium text-slate-700">No hardening checks recorded</p>
                <p className="text-sm text-slate-500">Run a scan to populate findings.</p>
              </div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr>
                    <th className={thClass}>Status</th>
                    <th className={thClass}>Severity</th>
                    <th className={thClass}>Category</th>
                    <th className={thClass}>Title</th>
                    <th className={thClass}>Observed</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {checks.map((c) => (
                    <tr key={c.id}>
                      <td className={tdClass}>{statusIcon(c.status)}</td>
                      <td className={`${tdClass} ${severityClass(c.severity)}`}>{c.severity}</td>
                      <td className={tdClass}>{c.category}</td>
                      <td className={tdClass}>{c.title}</td>
                      <td className="px-4 py-3 text-xs text-slate-500">{formatTs(c.observed_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {tab === 'ssh' && (
        <div className="space-y-5">
          <button type="button" className={primaryButtonClass}
            onClick={() => { void loadSSHPosture(); }}
            disabled={postureLoading}>
            {postureLoading ? 'Reading…' : 'Read SSH Posture'}
          </button>
          {posture && (
            <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-100">
                <h3 className="text-sm font-semibold text-slate-900">SSH Configuration</h3>
              </div>
              <ul className="divide-y divide-slate-100">
                {([
                  ['Port', String(posture.port), posture.port !== 22 ? '✅' : '⚠️'],
                  ['PermitRootLogin', posture.permit_root_login, posture.permit_root_login === 'no' ? '✅' : '❌'],
                  ['PasswordAuthentication', posture.password_auth, posture.password_auth === 'no' ? '✅' : '❌'],
                  ['PubkeyAuthentication', posture.pubkey_auth, posture.pubkey_auth === 'yes' ? '✅' : '⚠️'],
                  ['Protocol', posture.protocol_versions || '2', '✅'],
                  ['Active sessions', String(posture.active_sessions), ''],
                  ['Auth failures (1h)', String(posture.auth_failures_1h), posture.auth_failures_1h > 10 ? '⚠️' : '✅'],
                  ['Observed', formatTs(posture.observed_at), ''],
                ] as [string, string, string][]).map(([label, value, icon]) => (
                  <li key={label} className="flex items-center gap-4 px-6 py-3">
                    <span className="text-base w-6 shrink-0">{icon}</span>
                    <span className="text-xs text-slate-500 w-48 shrink-0">{label}</span>
                    <span className="font-mono text-sm text-slate-800">{value}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {tab === 'events' && (
        <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
          {events.length === 0 && !loading ? (
            <div className="flex flex-col items-center py-12 gap-2 text-center">
              <span className="text-3xl">📋</span>
              <p className="font-medium text-slate-700">No security events</p>
              <p className="text-sm text-slate-500">Events will appear here when detected.</p>
            </div>
          ) : (
            <ul className="divide-y divide-slate-100">
              {events.map((e) => (
                <li key={e.id} className="flex items-start gap-4 px-6 py-4">
                  <span className="text-xl shrink-0 mt-0.5">{eventKindIcon(e.kind)}</span>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-slate-800">{e.kind}</p>
                    <p className="text-xs text-slate-500 mt-0.5">
                      {e.source && <span className="mr-2">{e.source}</span>}
                      {e.remote_ip && <span className="font-mono mr-2">{e.remote_ip}</span>}
                      {e.service && <span>{e.service}</span>}
                    </p>
                  </div>
                  <span className="text-xs text-slate-400 shrink-0 mt-0.5">{formatTs(e.observed_at)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {tab === 'bans' && (
        <div className="space-y-5">
          <div className="flex gap-2">
            <button type="button" className={primaryButtonClass}
              onClick={withStepUp(async () => setShowCreateBan(true))}>+ Ban IP</button>
            <button type="button" className={secondaryButtonClass}
              onClick={() => { void loadLiveBans(); }}>
              {liveLoading ? 'Reading…' : 'Read live bans'}
            </button>
          </div>

          <Modal
            isOpen={showCreateBan}
            onClose={() => setShowCreateBan(false)}
            title="Ban IP Address"
          >
            <form className="space-y-4"
              onSubmit={(e) => { e.preventDefault(); void handleCreateBan(); }}>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="IP address">
                  <input className={inputClass} required value={newBan.ip}
                    onChange={(e) => setNewBan({ ...newBan, ip: e.target.value })} />
                </Field>
                <Field label="Source">
                  <select className={inputClass} value={newBan.source}
                    onChange={(e) => setNewBan({ ...newBan, source: e.target.value })}>
                    {['manual', 'fail2ban', 'crowdsec'].map((s) => <option key={s}>{s}</option>)}
                  </select>
                </Field>
                <div className="sm:col-span-2">
                  <Field label="Reason">
                    <input className={inputClass} value={newBan.reason}
                      onChange={(e) => setNewBan({ ...newBan, reason: e.target.value })} />
                  </Field>
                </div>
              </div>
              <div className="flex gap-2 justify-end pt-2">
                <button type="button" className={secondaryButtonClass} onClick={() => setShowCreateBan(false)}>Cancel</button>
                <button type="submit" className={primaryButtonClass}>Ban</button>
              </div>
            </form>
          </Modal>

          {liveBans != null && (
            <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-100">
                <h3 className="text-sm font-semibold text-slate-900">Live bans from node ({liveBans.length})</h3>
              </div>
              {liveBans.length === 0 ? (
                <div className="flex flex-col items-center py-8 gap-2 text-center">
                  <span className="text-2xl">✅</span>
                  <p className="text-sm text-slate-500">No live bans.</p>
                </div>
              ) : (
                <table className="w-full">
                  <thead>
                    <tr>
                      <th className={thClass}>IP</th>
                      <th className={thClass}>Source</th>
                      <th className={thClass}>Jail</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {liveBans.map((b, i) => (
                      <tr key={i}>
                        <td className="px-4 py-3 font-mono text-xs text-slate-800">{b.ip}</td>
                        <td className={tdClass}>{b.source}</td>
                        <td className="px-4 py-3 text-xs text-slate-600">{b.jail || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-100">
              <h3 className="text-sm font-semibold text-slate-900">Active bans</h3>
            </div>
            {bans.length === 0 && !loading ? (
              <div className="flex flex-col items-center py-12 gap-2 text-center">
                <span className="text-3xl">✅</span>
                <p className="font-medium text-slate-700">No active bans</p>
                <p className="text-sm text-slate-500">No IPs are currently banned.</p>
              </div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr>
                    <th className={thClass}>IP</th>
                    <th className={thClass}>Source</th>
                    <th className={thClass}>Reason</th>
                    <th className={thClass}>Banned at</th>
                    <th className={thClass}></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {bans.map((b) => (
                    <tr key={b.id}>
                      <td className="px-4 py-3 font-mono text-xs text-slate-800">{b.ip}</td>
                      <td className={tdClass}>{b.source}</td>
                      <td className="px-4 py-3 text-xs text-slate-600">{b.reason || '-'}</td>
                      <td className="px-4 py-3 text-xs text-slate-500">{formatTs(b.banned_at)}</td>
                      <td className="px-4 py-3">
                        <button type="button"
                          className="rounded-lg bg-red-600 px-3 py-1 text-xs font-medium text-white hover:bg-red-700"
                          onClick={withStepUp(async () => {
                            await securityCenterApi.removeBan(serverId, b.id);
                            goeyToast.success('Ban removed');
                            loadData();
                          })}>Unban</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {tab === 'waf' && (
        <div className="space-y-5">
          <button type="button" className={primaryButtonClass}
            onClick={withStepUp(async () => setShowCreateWAF(true))}>+ Rule</button>

          <Modal
            isOpen={showCreateWAF}
            onClose={() => setShowCreateWAF(false)}
            title="New WAF Rule"
          >
            <form className="space-y-4"
              onSubmit={(e) => { e.preventDefault(); void handleCreateWAF(); }}>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Kind">
                  <select className={inputClass} value={newWAF.kind}
                    onChange={(e) => setNewWAF({ ...newWAF, kind: e.target.value })}>
                    {['rate_limit', 'block_ua', 'block_ip', 'custom'].map((k) => <option key={k}>{k}</option>)}
                  </select>
                </Field>
                <Field label="Pattern">
                  <input className={inputClass} required value={newWAF.pattern}
                    onChange={(e) => setNewWAF({ ...newWAF, pattern: e.target.value })} />
                </Field>
                <Field label="Action">
                  <select className={inputClass} value={newWAF.action}
                    onChange={(e) => setNewWAF({ ...newWAF, action: e.target.value })}>
                    {['block', 'challenge', 'log'].map((a) => <option key={a}>{a}</option>)}
                  </select>
                </Field>
                <Field label="Priority">
                  <input className={inputClass} type="number" value={newWAF.priority}
                    onChange={(e) => setNewWAF({ ...newWAF, priority: e.target.value })} />
                </Field>
                <Field label="Description">
                  <input className={inputClass} value={newWAF.description}
                    onChange={(e) => setNewWAF({ ...newWAF, description: e.target.value })} />
                </Field>
                <Field label="Enabled">
                  <input type="checkbox" checked={newWAF.enabled}
                    onChange={(e) => setNewWAF({ ...newWAF, enabled: e.target.checked })} />
                </Field>
              </div>
              <div className="flex gap-2 justify-end pt-2">
                <button type="button" className={secondaryButtonClass} onClick={() => setShowCreateWAF(false)}>Cancel</button>
                <button type="submit" className={primaryButtonClass}>Create</button>
              </div>
            </form>
          </Modal>

          <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
            {wafRules.length === 0 && !loading ? (
              <div className="flex flex-col items-center py-12 gap-2 text-center">
                <span className="text-3xl">🛡️</span>
                <p className="font-medium text-slate-700">No WAF rules</p>
                <p className="text-sm text-slate-500">Add rules to filter malicious traffic.</p>
              </div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr>
                    <th className={thClass}>Kind</th>
                    <th className={thClass}>Pattern</th>
                    <th className={thClass}>Action</th>
                    <th className={thClass}>Priority</th>
                    <th className={thClass}>Enabled</th>
                    <th className={thClass}></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {wafRules.map((r) => (
                    <tr key={r.id}>
                      <td className={tdClass}>{r.kind}</td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-700 max-w-[12rem] truncate">{r.pattern}</td>
                      <td className="px-4 py-3">{wafActionBadge(r.action)}</td>
                      <td className={tdClass}>{r.priority}</td>
                      <td className="px-4 py-3">
                        <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${r.enabled ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-100 text-slate-500'}`}>
                          {r.enabled ? 'Yes' : 'No'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <button type="button"
                          className="rounded-lg bg-red-600 px-3 py-1 text-xs font-medium text-white hover:bg-red-700"
                          onClick={withStepUp(async () => {
                            await securityCenterApi.deleteWAFRule(serverId, r.id);
                            goeyToast.success('WAF rule deleted');
                            loadData();
                          })}>Delete</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
