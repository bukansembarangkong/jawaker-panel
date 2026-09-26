import { useCallback, useEffect, useState } from 'react';

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
  EmptyState,
  ErrorNote,
  Field,
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
    default:         return 'text-ink-secondary';
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

interface ServerOption { id: string; name: string; }

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
    return () => fn().catch((e: unknown) => {
      if (isStepUpRequired(e)) {
        setStepUpAction(() => fn);
        setStepUpPending(true);
      } else {
        setError(toError(e));
      }
    });
  }

  async function runScan() {
    setScanRunning(true);
    setFindings(null);
    try {
      const r = await securityCenterApi.triggerScan(serverId);
      setFindings(r.findings ?? []);
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
    await securityCenterApi.createBan(serverId, {
      ip: newBan.ip, reason: newBan.reason || undefined, source: newBan.source || undefined,
    });
    setShowCreateBan(false);
    setNewBan({ ip: '', reason: '', source: 'manual' });
    loadData();
  }

  async function handleCreateWAF() {
    await securityCenterApi.createWAFRule(serverId, {
      kind: newWAF.kind, pattern: newWAF.pattern, action: newWAF.action,
      enabled: newWAF.enabled, priority: parseInt(newWAF.priority, 10) || 100,
      description: newWAF.description || undefined,
    });
    setShowCreateWAF(false);
    setNewWAF({ kind: 'rate_limit', pattern: '', action: 'block', enabled: true, priority: '100', description: '' });
    loadData();
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
      } else {
        await attackModeApi.enable(serverId);
      }
      await loadAttackMode(serverId);
    } catch (e) {
      setError(toError(e));
    } finally {
      setAttackModeLoading(false);
    }
  }

  const tabClass = (t: Tab) =>
    `px-3 py-1.5 text-sm rounded-md ${tab === t ? 'bg-elevated font-medium text-ink' : 'text-ink-secondary hover:text-ink'}`;

  if (!serverId) return <p className="text-sm text-ink-secondary">No servers available.</p>;

  return (
    <section className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h2 className="text-base font-semibold">Security Center</h2>
        <select className={inputClass} value={serverId} onChange={(e) => { setServerId(e.target.value); void loadAttackMode(e.target.value); }} aria-label="Select server">
          {servers.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
      </div>

      {/* Under Attack Mode Banner (PRD §21.4) */}
      <div className={`rounded-lg border p-4 flex items-center justify-between ${
        attackMode?.enabled
          ? 'border-red-400 bg-red-50 dark:bg-red-950/20'
          : 'border-border bg-surface'
      }`}>
        <div>
          <p className={`text-sm font-semibold ${attackMode?.enabled ? 'text-red-700 dark:text-red-400' : 'text-ink'}`}>
            {attackMode?.enabled ? '🚨 Under Attack Mode - ACTIVE' : 'Under Attack Mode'}
          </p>
          <p className="text-xs text-ink-secondary mt-0.5">
            {attackMode?.enabled
              ? `Activated: ${attackMode.activated_at ? new Date(attackMode.activated_at).toLocaleString() : 'just now'}. Rate limits tightened ${attackMode.rate_limit_multiplier}×. Suspicious traffic challenged.`
              : 'Temporarily tightens rate limits, challenges suspicious traffic, restricts expensive endpoints.'}
          </p>
        </div>
        <button
          onClick={() => void handleToggleAttackMode()}
          disabled={attackModeLoading}
          className={`rounded-md px-4 py-1.5 text-sm font-medium text-white disabled:opacity-50 ${
            attackMode?.enabled ? 'bg-green-600 hover:bg-green-700' : 'bg-red-600 hover:bg-red-700'
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

      <nav aria-label="Security tabs" className="flex flex-wrap gap-2">
        {(['hardening', 'ssh', 'events', 'bans', 'waf'] as Tab[]).map((t) => (
          <button key={t} type="button" className={tabClass(t)} onClick={() => setTab(t)}>
            {t === 'hardening' ? 'Hardening' :
             t === 'ssh' ? 'SSH Posture' :
             t === 'events' ? 'Events' :
             t === 'bans' ? 'Bans' : 'WAF Rules'}
          </button>
        ))}
      </nav>

      {loading && <p className="text-sm text-ink-secondary">Loading…</p>}

      {/* ─── Hardening ─── */}
      {tab === 'hardening' && (
        <div className="space-y-4">
          <button type="button" className={primaryButtonClass}
            onClick={() => { void runScan(); }}
            disabled={scanRunning}>
            {scanRunning ? 'Scanning…' : 'Run Scan'}
          </button>

          {findings != null && (
            <div className="space-y-2">
              <h3 className="text-sm font-medium">Scan results ({findings.length} findings)</h3>
              {findings.length === 0 ? (
                <p className="text-sm text-ink-secondary">No findings - all checks passed.</p>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-line text-left text-ink-secondary">
                      <th className="py-2 pr-4">Status</th>
                      <th className="py-2 pr-4">Severity</th>
                      <th className="py-2 pr-4">Check</th>
                      <th className="py-2 pr-4">Title</th>
                      <th className="py-2">Remediation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((f, i) => (
                      <tr key={i} className="border-b border-line">
                        <td className="py-2 pr-4">{statusIcon(f.status)}</td>
                        <td className={`py-2 pr-4 ${severityClass(f.severity)}`}>{f.severity}</td>
                        <td className="py-2 pr-4 font-mono text-xs">{f.check_name}</td>
                        <td className="py-2 pr-4">{f.title}</td>
                        <td className="py-2 text-xs text-ink-secondary">{f.remediation || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          <div className="space-y-2">
            <h3 className="text-sm font-medium">Stored checks</h3>
            {checks.length === 0 && !loading ? (
              <EmptyState title="No hardening checks recorded.">
                <span>Run a scan to populate findings.</span>
              </EmptyState>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line text-left text-ink-secondary">
                    <th className="py-2 pr-4">Status</th>
                    <th className="py-2 pr-4">Severity</th>
                    <th className="py-2 pr-4">Category</th>
                    <th className="py-2 pr-4">Title</th>
                    <th className="py-2">Observed</th>
                  </tr>
                </thead>
                <tbody>
                  {checks.map((c) => (
                    <tr key={c.id} className="border-b border-line">
                      <td className="py-2 pr-4">{statusIcon(c.status)}</td>
                      <td className={`py-2 pr-4 ${severityClass(c.severity)}`}>{c.severity}</td>
                      <td className="py-2 pr-4">{c.category}</td>
                      <td className="py-2 pr-4">{c.title}</td>
                      <td className="py-2 text-xs text-ink-secondary">{formatTs(c.observed_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ─── SSH Posture ─── */}
      {tab === 'ssh' && (
        <div className="space-y-4">
          <button type="button" className={primaryButtonClass}
            onClick={() => { void loadSSHPosture(); }}
            disabled={postureLoading}>
            {postureLoading ? 'Reading…' : 'Read SSH Posture'}
          </button>
          {posture && (
            <table className="w-full max-w-lg text-sm">
              <tbody>
                {([
                  ['Port', String(posture.port)],
                  ['PermitRootLogin', posture.permit_root_login],
                  ['PasswordAuthentication', posture.password_auth],
                  ['PubkeyAuthentication', posture.pubkey_auth],
                  ['Protocol', posture.protocol_versions || '2'],
                  ['Active sessions', String(posture.active_sessions)],
                  ['Auth failures (1h)', String(posture.auth_failures_1h)],
                  ['Observed', formatTs(posture.observed_at)],
                ] as [string, string][]).map(([label, value]) => (
                  <tr key={label} className="border-b border-line">
                    <td className="py-2 pr-4 text-ink-secondary text-xs">{label}</td>
                    <td className="py-2 font-mono text-xs">{value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ─── Events ─── */}
      {tab === 'events' && (
        <div className="space-y-4">
          {events.length === 0 && !loading ? (
            <EmptyState title="No security events recorded."><span /></EmptyState>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-ink-secondary">
                  <th className="py-2 pr-4">When</th>
                  <th className="py-2 pr-4">Kind</th>
                  <th className="py-2 pr-4">Source</th>
                  <th className="py-2 pr-4">Remote IP</th>
                  <th className="py-2">Service</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id} className="border-b border-line">
                    <td className="py-2 pr-4 text-xs text-ink-secondary">{formatTs(e.observed_at)}</td>
                    <td className="py-2 pr-4">{e.kind}</td>
                    <td className="py-2 pr-4">{e.source}</td>
                    <td className="py-2 pr-4 font-mono text-xs">{e.remote_ip || '-'}</td>
                    <td className="py-2 text-xs">{e.service || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ─── Bans ─── */}
      {tab === 'bans' && (
        <div className="space-y-4">
          <div className="flex gap-2">
            <button type="button" className={secondaryButtonClass}
              onClick={withStepUp(async () => setShowCreateBan(true))}>+ Ban IP</button>
            <button type="button" className={secondaryButtonClass}
              onClick={() => { void loadLiveBans(); }}>
              {liveLoading ? 'Reading…' : 'Read live bans'}
            </button>
          </div>

          {showCreateBan && (
            <form className="space-y-3 rounded-md border border-line p-4"
              onSubmit={(e) => { e.preventDefault(); void handleCreateBan(); }}>
              <h3 className="text-sm font-medium">Ban IP</h3>
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
                <Field label="Reason">
                  <input className={inputClass} value={newBan.reason}
                    onChange={(e) => setNewBan({ ...newBan, reason: e.target.value })} />
                </Field>
              </div>
              <div className="flex gap-2">
                <button type="submit" className={primaryButtonClass}>Ban</button>
                <button type="button" className={secondaryButtonClass} onClick={() => setShowCreateBan(false)}>Cancel</button>
              </div>
            </form>
          )}

          {liveBans != null && (
            <div className="space-y-2">
              <h3 className="text-sm font-medium">Live bans from node ({liveBans.length})</h3>
              {liveBans.length === 0 ? (
                <p className="text-sm text-ink-secondary">No live bans.</p>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-line text-left text-ink-secondary">
                      <th className="py-2 pr-4">IP</th>
                      <th className="py-2 pr-4">Source</th>
                      <th className="py-2">Jail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {liveBans.map((b, i) => (
                      <tr key={i} className="border-b border-line">
                        <td className="py-2 pr-4 font-mono text-xs">{b.ip}</td>
                        <td className="py-2 pr-4">{b.source}</td>
                        <td className="py-2 text-xs">{b.jail || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {bans.length === 0 && !loading ? (
            <EmptyState title="No active bans."><span /></EmptyState>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-ink-secondary">
                  <th className="py-2 pr-4">IP</th>
                  <th className="py-2 pr-4">Source</th>
                  <th className="py-2 pr-4">Reason</th>
                  <th className="py-2 pr-4">Banned</th>
                  <th className="py-2"></th>
                </tr>
              </thead>
              <tbody>
                {bans.map((b) => (
                  <tr key={b.id} className="border-b border-line">
                    <td className="py-2 pr-4 font-mono text-xs">{b.ip}</td>
                    <td className="py-2 pr-4">{b.source}</td>
                    <td className="py-2 pr-4 text-xs">{b.reason || '-'}</td>
                    <td className="py-2 pr-4 text-xs text-ink-secondary">{formatTs(b.banned_at)}</td>
                    <td className="py-2">
                      <button type="button" className={secondaryButtonClass}
                        onClick={withStepUp(async () => {
                          await securityCenterApi.removeBan(serverId, b.id);
                          loadData();
                        })}>Unban</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ─── WAF Rules ─── */}
      {tab === 'waf' && (
        <div className="space-y-4">
          <button type="button" className={secondaryButtonClass}
            onClick={withStepUp(async () => setShowCreateWAF(true))}>+ Rule</button>

          {showCreateWAF && (
            <form className="space-y-3 rounded-md border border-line p-4"
              onSubmit={(e) => { e.preventDefault(); void handleCreateWAF(); }}>
              <h3 className="text-sm font-medium">New WAF Rule</h3>
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
              <div className="flex gap-2">
                <button type="submit" className={primaryButtonClass}>Create</button>
                <button type="button" className={secondaryButtonClass} onClick={() => setShowCreateWAF(false)}>Cancel</button>
              </div>
            </form>
          )}

          {wafRules.length === 0 && !loading ? (
            <EmptyState title="No WAF rules configured."><span /></EmptyState>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-ink-secondary">
                  <th className="py-2 pr-4">Kind</th>
                  <th className="py-2 pr-4">Pattern</th>
                  <th className="py-2 pr-4">Action</th>
                  <th className="py-2 pr-4">Priority</th>
                  <th className="py-2 pr-4">Enabled</th>
                  <th className="py-2"></th>
                </tr>
              </thead>
              <tbody>
                {wafRules.map((r) => (
                  <tr key={r.id} className="border-b border-line">
                    <td className="py-2 pr-4">{r.kind}</td>
                    <td className="py-2 pr-4 font-mono text-xs max-w-[12rem] truncate">{r.pattern}</td>
                    <td className="py-2 pr-4">{r.action}</td>
                    <td className="py-2 pr-4">{r.priority}</td>
                    <td className="py-2 pr-4">{r.enabled ? 'Yes' : 'No'}</td>
                    <td className="py-2">
                      <button type="button" className={secondaryButtonClass}
                        onClick={withStepUp(async () => {
                          await securityCenterApi.deleteWAFRule(serverId, r.id);
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
    </section>
  );
}
