import { useCallback, useEffect, useState } from 'react';
import { goeyToast } from 'goey-toast';
import {
  observeApi,
  type AlertIncident,
  type AlertRule,
  type ReportSchedule,
  type Server,
  type SLOSummary,
} from '../api/client';
import {
  ConfirmModal,
  ErrorNote,
  Field,
} from '../components/ui';
import { api } from '../api/client';

function formatTs(value: string | null | undefined): string {
  if (!value) return '-';
  try { return new Date(value).toLocaleString(); } catch { return value; }
}

function toError(e: unknown): Error {
  return e instanceof Error ? e : new Error(String(e));
}

function getCadenceCron(cadence: string): string {
  switch (cadence) {
    case 'daily': return '0 0 * * *';
    case 'weekly': return '0 0 * * 0';
    case 'monthly': return '0 0 1 * *';
    default: return '0 * * * *';
  }
}

type Tab = 'incidents' | 'rules' | 'schedules';

export function ObservabilityPage() {
  const [tab, setTab] = useState<Tab>('incidents');
  const [servers, setServers] = useState<Server[]>([]);
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [incidents, setIncidents] = useState<AlertIncident[]>([]);
  const [schedules, setSchedules] = useState<ReportSchedule[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [confirmState, setConfirmState] = useState<{ open: boolean; message: string; onConfirm: () => void }>({ open: false, message: '', onConfirm: () => {} });

  const [showRuleForm, setShowRuleForm] = useState(false);
  const [newRule, setNewRule] = useState({
    server_id: '',
    name: '',
    metric: 'cpu_pct',
    comparator: 'gt' as 'gt' | 'lt',
    threshold: 90,
    duration_seconds: 300,
    severity: 'warning' as 'info' | 'warning' | 'critical',
  });

  const [showSchedForm, setShowSchedForm] = useState(false);
  const [newSched, setNewSched] = useState({ name: '', cadence: 'daily' as 'daily' | 'weekly' | 'monthly' });
  const [incidentStateFilter, setIncidentStateFilter] = useState<'' | 'open' | 'resolved'>('open');
  const [slo, setSlo] = useState<SLOSummary | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [srvRes, rulesRes, incsRes, schedsRes, sloRes] = await Promise.all([
        api.listServers(),
        observeApi.listRules(),
        observeApi.listIncidents(undefined, incidentStateFilter || undefined),
        observeApi.listSchedules(),
        observeApi.getSLOSummary().catch(() => null),
      ]);
      setServers(srvRes.servers ?? []);
      setRules(rulesRes.rules ?? []);
      setIncidents(incsRes.incidents ?? []);
      setSchedules(schedsRes.schedules ?? []);
      setSlo(sloRes?.slo ?? null);
    } catch (e) {
      setError(toError(e));
    } finally {
      setLoading(false);
    }
  }, [incidentStateFilter]);

  useEffect(() => { void load(); }, [load]);

  async function handleCreateRule() {
    try { await observeApi.createRule(newRule); setShowRuleForm(false); goeyToast.success('Alert rule created.'); void load(); }
    catch (e) { setError(toError(e)); }
  }

  async function handleToggleRule(rule: AlertRule) {
    try { await observeApi.updateRule(rule.id, { enabled: !rule.enabled }); goeyToast.success(`Rule ${rule.enabled ? 'disabled' : 'enabled'}.`); void load(); }
    catch (e) { setError(toError(e)); }
  }

  async function handleDeleteRule(rule: AlertRule) {
    setConfirmState({
      open: true, message: `Delete rule "${rule.name}"?`,
      onConfirm: async () => {
        try { await observeApi.deleteRule(rule.id); goeyToast.success('Rule deleted.'); void load(); }
        catch (e) { setError(toError(e)); }
      },
    });
  }

  async function handleResolveIncident(inc: AlertIncident) {
    try { await observeApi.resolveIncident(inc.id); goeyToast.success('Incident resolved.'); void load(); }
    catch (e) { setError(toError(e)); }
  }

  async function handleCreateSchedule() {
    try { await observeApi.createSchedule(newSched); setShowSchedForm(false); goeyToast.success('Schedule created.'); void load(); }
    catch (e) { setError(toError(e)); }
  }

  async function handleDeleteSchedule(s: ReportSchedule) {
    setConfirmState({
      open: true, message: `Delete schedule "${s.name}"?`,
      onConfirm: async () => {
        try { await observeApi.deleteSchedule(s.id); goeyToast.success('Schedule deleted.'); void load(); }
        catch (e) { setError(toError(e)); }
      },
    });
  }

  const inputCls = 'block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none';
  const btnPrimary = 'rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all';
  const btnSecondary = 'rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all';
  const btnSmDanger = 'rounded-lg bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700 transition-all';
  const tabCls = (t: Tab) =>
    `pb-2 text-sm font-medium border-b-2 transition-all ${tab === t ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500 hover:text-slate-800'}`;

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

      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Observability</h1>
          <p className="text-sm text-slate-500">Service Level Objectives, active alerts, incident tracking, and report cadences.</p>
        </div>
        {loading && <span className="text-sm text-slate-500">Loading?</span>}
      </div>

      {error && <ErrorNote error={error} />}

      {slo && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">Error Budget</span>
            <div className="mt-2 flex items-baseline justify-between">
              <span className={`text-2xl font-bold ${slo.error_budget_remaining_pct < 50 ? 'text-red-600' : 'text-emerald-600'}`}>
                {slo.error_budget_remaining_pct.toFixed(1)}%
              </span>
              <span className="text-xs text-slate-400">remaining</span>
            </div>
            <div className="mt-3 w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
              <div
                className={`h-1.5 rounded-full ${slo.error_budget_remaining_pct < 50 ? 'bg-red-500' : 'bg-emerald-500'}`}
                style={{ width: `${Math.min(100, Math.max(0, slo.error_budget_remaining_pct))}%` }}
              />
            </div>
          </div>
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">Controller Availability</span>
            <div className="mt-2 flex items-baseline justify-between">
              <span className={`text-2xl font-bold ${slo.controller_availability_pct < 99 ? 'text-amber-600' : 'text-slate-900'}`}>
                {slo.controller_availability_pct.toFixed(2)}%
              </span>
              <span className="text-xs text-slate-400">target 99.9%</span>
            </div>
            <p className="mt-2 text-xs text-slate-500">Node connectivity: {slo.node_connectivity_pct.toFixed(1)}%</p>
          </div>
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">Success Rates</span>
            <div className="mt-2 flex items-baseline justify-between">
              <span className="text-2xl font-bold text-slate-900">{slo.deployment_success_rate_pct.toFixed(1)}%</span>
              <span className="text-xs text-slate-400">deploys</span>
            </div>
            <p className="mt-2 text-xs text-slate-500">Backups: {slo.backup_success_rate_pct.toFixed(1)}%</p>
          </div>
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">Active Incidents</span>
            <div className="mt-2 flex items-baseline justify-between">
              <span className={`text-2xl font-bold ${slo.active_incidents > 0 ? 'text-red-600' : 'text-slate-900'}`}>{slo.active_incidents}</span>
              <span className="text-xs text-slate-400">avg {Math.round(slo.job_latency_avg_ms)}ms</span>
            </div>
            <p className="mt-2 text-xs text-slate-400">Evaluated: {formatTs(slo.evaluated_at)}</p>
          </div>
        </div>
      )}

      <div className="flex border-b border-slate-200 gap-4">
        <button className={tabCls('incidents')} onClick={() => setTab('incidents')}>Incidents</button>
        <button className={tabCls('rules')} onClick={() => setTab('rules')}>Alert Rules</button>
        <button className={tabCls('schedules')} onClick={() => setTab('schedules')}>Report Schedules</button>
      </div>

      {tab === 'incidents' && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-slate-500 uppercase">Filter:</span>
            {(['open', 'resolved', ''] as const).map((v) => (
              <button
                key={v || 'all'}
                className={`rounded-full px-3 py-1 text-xs font-medium transition-all ${incidentStateFilter === v ? 'bg-indigo-600 text-white shadow-sm' : 'border border-slate-200 bg-white text-slate-600 hover:bg-slate-50'}`}
                onClick={() => setIncidentStateFilter(v)}
              >
                {v ? v.charAt(0).toUpperCase() + v.slice(1) : 'All'}
              </button>
            ))}
          </div>
          {incidents.length === 0 ? (
            <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
              <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100"><svg className="h-6 w-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" /></svg></div>
              <h3 className="text-base font-semibold text-slate-900">No incidents</h3>
              <p className="text-sm text-slate-500 mt-1">No incidents match the selected state filter.</p>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="relative pl-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200 space-y-6">
                {incidents.map((inc) => {
                  const srv = servers.find((s) => s.id === inc.server_id);
                  const isOpen = inc.state === 'open';
                  return (
                    <div key={inc.id} className="relative flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                      <div className={`absolute -left-6 top-1.5 h-3 w-3 rounded-full border-2 border-white ring-2 ${isOpen ? 'bg-red-500 ring-red-200' : 'bg-emerald-500 ring-emerald-200'}`} />
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${isOpen ? 'bg-red-50 text-red-700 border border-red-200' : 'bg-emerald-50 text-emerald-700 border border-emerald-200'}`}>
                            {isOpen ? 'Open' : 'Resolved'}
                          </span>
                          <span className="font-semibold text-sm text-slate-900">{srv?.name ?? inc.server_id.slice(0, 8)}</span>
                          <span className="font-mono text-xs text-slate-500">[{inc.dedup_key}]</span>
                        </div>
                        <div className="text-xs text-slate-500 flex items-center gap-4">
                          <span>Opened: {formatTs(inc.opened_at)}</span>
                          {inc.resolved_at && <span>Resolved: {formatTs(inc.resolved_at)}</span>}
                        </div>
                      </div>
                      {isOpen && (
                        <button className={btnSecondary} onClick={() => void handleResolveIncident(inc)}>Resolve</button>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'rules' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button className={btnPrimary} onClick={() => setShowRuleForm((v) => !v)}>
              {showRuleForm ? 'Cancel' : '+ New Rule'}
            </button>
          </div>
          {showRuleForm && (
            <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
              <h3 className="font-semibold text-slate-900">Create Alert Rule</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <Field label="Server">
                  <select className={inputCls} value={newRule.server_id} onChange={(e) => setNewRule({ ...newRule, server_id: e.target.value })}>
                    <option value="">- select server -</option>
                    {servers.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
                  </select>
                </Field>
                <Field label="Name">
                  <input className={inputCls} value={newRule.name} onChange={(e) => setNewRule({ ...newRule, name: e.target.value })} />
                </Field>
                <Field label="Metric">
                  <select className={inputCls} value={newRule.metric} onChange={(e) => setNewRule({ ...newRule, metric: e.target.value })}>
                    {['cpu_pct', 'mem_pct', 'disk_pct', 'load1'].map((m) => <option key={m}>{m}</option>)}
                  </select>
                </Field>
                <Field label="Comparator">
                  <select className={inputCls} value={newRule.comparator} onChange={(e) => setNewRule({ ...newRule, comparator: e.target.value as 'gt' | 'lt' })}>
                    <option value="gt">{'>'} gt (above)</option>
                    <option value="lt">{'<'} lt (below)</option>
                  </select>
                </Field>
                <Field label="Threshold">
                  <input type="number" className={inputCls} value={newRule.threshold} onChange={(e) => setNewRule({ ...newRule, threshold: Number(e.target.value) })} />
                </Field>
                <Field label="Duration (seconds)">
                  <input type="number" className={inputCls} value={newRule.duration_seconds} onChange={(e) => setNewRule({ ...newRule, duration_seconds: Number(e.target.value) })} />
                </Field>
                <Field label="Severity">
                  <select className={inputCls} value={newRule.severity} onChange={(e) => setNewRule({ ...newRule, severity: e.target.value as 'info' | 'warning' | 'critical' })}>
                    <option value="info">Info</option>
                    <option value="warning">Warning</option>
                    <option value="critical">Critical</option>
                  </select>
                </Field>
              </div>
              <div className="flex gap-2 justify-end pt-2">
                <button className={btnSecondary} onClick={() => setShowRuleForm(false)}>Cancel</button>
                <button className={btnPrimary} onClick={() => void handleCreateRule()}>Create</button>
              </div>
            </div>
          )}
          {rules.length === 0 ? (
            <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
              <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100"><svg className="h-6 w-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" /></svg></div>
              <h3 className="text-base font-semibold text-slate-900">No alert rules</h3>
              <p className="text-sm text-slate-500 mt-1">Create a rule to start monitoring metric thresholds.</p>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr className="border-b border-slate-200">
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Severity</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Name</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Server</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Condition</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Duration</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Status</th>
                      <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {rules.map((rule) => {
                      const srv = servers.find((s) => s.id === rule.server_id);
                      return (
                        <tr key={rule.id} className="hover:bg-slate-50/50 transition-colors">
                          <td className="px-4 py-3 text-sm">
                            <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium uppercase ${
                              rule.severity === 'critical' ? 'bg-red-50 text-red-700 border border-red-200' :
                              rule.severity === 'warning' ? 'bg-amber-50 text-amber-700 border border-amber-200' :
                              'bg-blue-50 text-blue-700 border border-blue-200'
                            }`}>
                              {rule.severity}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-sm font-medium text-slate-900">{rule.name}</td>
                          <td className="px-4 py-3 text-sm text-slate-600">{srv?.name ?? rule.server_id.slice(0, 8)}</td>
                          <td className="px-4 py-3 text-sm font-mono text-slate-700">{rule.metric} {rule.comparator} {rule.threshold}</td>
                          <td className="px-4 py-3 text-sm text-slate-500">{rule.duration_seconds}s</td>
                          <td className="px-4 py-3 text-sm">
                            <button
                              type="button"
                              onClick={() => void handleToggleRule(rule)}
                              className={`rounded-full px-2.5 py-0.5 text-xs font-medium transition-all ${rule.enabled ? 'bg-emerald-50 text-emerald-700 border border-emerald-200 hover:bg-emerald-100' : 'bg-slate-100 text-slate-600 border border-slate-200 hover:bg-slate-200'}`}
                            >
                              {rule.enabled ? 'Enabled' : 'Disabled'}
                            </button>
                          </td>
                          <td className="px-4 py-3 text-sm text-right">
                            <button className={btnSmDanger} onClick={() => void handleDeleteRule(rule)}>Delete</button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'schedules' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button className={btnPrimary} onClick={() => setShowSchedForm((v) => !v)}>
              {showSchedForm ? 'Cancel' : '+ New Schedule'}
            </button>
          </div>
          {showSchedForm && (
            <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
              <h3 className="font-semibold text-slate-900">Create Report Schedule</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <Field label="Name">
                  <input className={inputCls} value={newSched.name} onChange={(e) => setNewSched({ ...newSched, name: e.target.value })} />
                </Field>
                <Field label="Cadence">
                  <select className={inputCls} value={newSched.cadence} onChange={(e) => setNewSched({ ...newSched, cadence: e.target.value as 'daily' | 'weekly' | 'monthly' })}>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </Field>
              </div>
              <div className="flex gap-2 justify-end pt-2">
                <button className={btnSecondary} onClick={() => setShowSchedForm(false)}>Cancel</button>
                <button className={btnPrimary} onClick={() => void handleCreateSchedule()}>Create</button>
              </div>
            </div>
          )}
          {schedules.length === 0 ? (
            <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
              <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100"><svg className="h-6 w-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" /></svg></div>
              <h3 className="text-base font-semibold text-slate-900">No report schedules</h3>
              <p className="text-sm text-slate-500 mt-1">Create a schedule to receive periodic summary reports.</p>
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2">
              {schedules.map((s) => (
                <div key={s.id} className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between space-y-4">
                  <div>
                    <div className="flex items-center justify-between">
                      <h4 className="text-base font-semibold text-slate-900">{s.name}</h4>
                      <span className="rounded-full px-2.5 py-0.5 text-xs font-mono font-medium bg-indigo-50 text-indigo-700 border border-indigo-200">
                        {getCadenceCron(s.cadence)} ({s.cadence})
                      </span>
                    </div>
                    <div className="mt-3 space-y-1 text-xs text-slate-500">
                      <p>Next run: <span className="text-slate-700 font-medium">{formatTs(s.next_run_at)}</span></p>
                      <p>Last run: <span className="text-slate-700 font-medium">{formatTs(s.last_run_at)}</span></p>
                    </div>
                  </div>
                  <div className="flex justify-end pt-2 border-t border-slate-100">
                    <button className={btnSmDanger} onClick={() => void handleDeleteSchedule(s)}>Delete</button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
