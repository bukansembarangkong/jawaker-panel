import { useCallback, useEffect, useState } from 'react';

import {
  observeApi,
  type AlertIncident,
  type AlertRule,
  type ReportSchedule,
  type Server,
  type SLOSummary,
} from '../api/client';
import {
  EmptyState,
  ErrorNote,
  Field,
  StatusBadge,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
  type OperationalState,
} from '../components/ui';
import { api } from '../api/client';

function incidentState(i: AlertIncident): OperationalState {
  return i.state === 'open' ? 'Disabled' : 'Healthy';
}

function ruleState(r: AlertRule): OperationalState {
  if (!r.enabled || r.state === 'suspended') return 'Disabled';
  return 'Healthy';
}

function formatTs(value: string | null | undefined): string {
  if (!value) return '-';
  try { return new Date(value).toLocaleString(); } catch { return value; }
}

function toError(e: unknown): Error {
  return e instanceof Error ? e : new Error(String(e));
}

type Tab = 'rules' | 'incidents' | 'schedules';

export function ObservabilityPage() {
  const [tab, setTab] = useState<Tab>('incidents');
  const [servers, setServers] = useState<Server[]>([]);
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [incidents, setIncidents] = useState<AlertIncident[]>([]);
  const [schedules, setSchedules] = useState<ReportSchedule[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  // Create rule form
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

  // Create schedule form
  const [showSchedForm, setShowSchedForm] = useState(false);
  const [newSched, setNewSched] = useState({ name: '', cadence: 'daily' as 'daily' | 'weekly' | 'monthly' });

  // Incident filter
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
    try {
      await observeApi.createRule(newRule);
      setShowRuleForm(false);
      setMsg('Alert rule created.');
      void load();
    } catch (e) { setError(toError(e)); }
  }

  async function handleToggleRule(rule: AlertRule) {
    try {
      await observeApi.updateRule(rule.id, { enabled: !rule.enabled });
      void load();
    } catch (e) { setError(toError(e)); }
  }

  async function handleDeleteRule(rule: AlertRule) {
    if (!confirm(`Delete rule "${rule.name}"?`)) return;
    try {
      await observeApi.deleteRule(rule.id);
      setMsg('Rule deleted.');
      void load();
    } catch (e) { setError(toError(e)); }
  }

  async function handleResolveIncident(inc: AlertIncident) {
    try {
      await observeApi.resolveIncident(inc.id);
      setMsg('Incident resolved.');
      void load();
    } catch (e) { setError(toError(e)); }
  }

  async function handleCreateSchedule() {
    try {
      await observeApi.createSchedule(newSched);
      setShowSchedForm(false);
      setMsg('Schedule created.');
      void load();
    } catch (e) { setError(toError(e)); }
  }

  async function handleDeleteSchedule(s: ReportSchedule) {
    if (!confirm(`Delete schedule "${s.name}"?`)) return;
    try {
      await observeApi.deleteSchedule(s.id);
      setMsg('Schedule deleted.');
      void load();
    } catch (e) { setError(toError(e)); }
  }

  const severityColor = (s: string) =>
    s === 'critical' ? 'text-red-600' : s === 'warning' ? 'text-yellow-600' : 'text-blue-600';

  const tabClass = (t: Tab) =>
    `px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
      tab === t
        ? 'border-indigo-500 text-indigo-600'
        : 'border-transparent text-gray-500 hover:text-gray-700'
    }`;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-gray-900">Observability</h1>
        {loading && <span className="text-sm text-gray-500">Loading…</span>}
      </div>

      {error && <ErrorNote error={error} />}
      {msg && (
        <div className="rounded-md bg-green-50 border border-green-200 px-4 py-2 text-sm text-green-800">
          {msg}
          <button className="ml-2 text-green-600 underline" onClick={() => setMsg(null)}>dismiss</button>
        </div>
      )}

      {/* SLO Summary (PRD §40) */}
      {slo && (
        <div className="rounded-lg border border-gray-200 bg-white p-4">
          <h2 className="text-sm font-semibold text-gray-700 mb-3">Service Level Objectives</h2>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {([
              { label: 'Controller availability', value: slo.controller_availability_pct, unit: '%', warn: 99 },
              { label: 'Node connectivity', value: slo.node_connectivity_pct, unit: '%', warn: 90 },
              { label: 'Backup success rate', value: slo.backup_success_rate_pct, unit: '%', warn: 95 },
              { label: 'Deploy success rate', value: slo.deployment_success_rate_pct, unit: '%', warn: 90 },
              { label: 'Job latency avg', value: slo.job_latency_avg_ms, unit: ' ms', warn: Infinity },
              { label: 'Error budget remaining', value: slo.error_budget_remaining_pct, unit: '%', warn: 50 },
              { label: 'Active incidents', value: slo.active_incidents, unit: '', warn: 0 },
            ] as { label: string; value: number; unit: string; warn: number }[]).map(({ label, value, unit, warn }) => {
              const bad = unit === '' ? value > warn : value < warn;
              return (
                <div key={label} className="flex flex-col">
                  <span className="text-xs text-gray-500">{label}</span>
                  <span className={`text-lg font-semibold ${bad ? 'text-red-600' : 'text-green-700'}`}>
                    {typeof value === 'number' && unit !== ' ms' ? value.toFixed(1) : Math.round(value)}{unit}
                  </span>
                </div>
              );
            })}
          </div>
          <p className="text-xs text-gray-400 mt-2">Evaluated: {formatTs(slo.evaluated_at)}</p>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200 flex gap-0">
        <button className={tabClass('incidents')} onClick={() => setTab('incidents')}>Incidents</button>
        <button className={tabClass('rules')} onClick={() => setTab('rules')}>Alert Rules</button>
        <button className={tabClass('schedules')} onClick={() => setTab('schedules')}>Report Schedules</button>
      </div>

      {/* ---- Incidents ---- */}
      {tab === 'incidents' && (
        <div className="space-y-4">
          <div className="flex gap-2 items-center">
            <label className="text-sm text-gray-600">State:</label>
            {(['open', 'resolved', ''] as const).map((v) => (
              <button
                key={v || 'all'}
                className={`px-3 py-1 rounded-full text-xs font-medium border ${incidentStateFilter === v ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white text-gray-600 border-gray-300'}`}
                onClick={() => setIncidentStateFilter(v)}
              >
                {v || 'all'}
              </button>
            ))}
          </div>
          {incidents.length === 0 ? (
            <EmptyState title="No incidents">No incidents match the current filter.</EmptyState>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-gray-200">
              <table className="min-w-full divide-y divide-gray-200 text-sm">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-3 text-left font-medium text-gray-500">State</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500">Server</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500">Dedup key</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500">Opened</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500">Resolved</th>
                    <th className="px-4 py-3" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 bg-white">
                  {incidents.map((inc) => {
                    const srv = servers.find((s) => s.id === inc.server_id);
                    return (
                      <tr key={inc.id}>
                        <td className="px-4 py-3"><StatusBadge state={incidentState(inc)} detail={inc.state} /></td>
                        <td className="px-4 py-3 text-gray-700">{srv?.name ?? inc.server_id.slice(0, 8)}</td>
                        <td className="px-4 py-3 font-mono text-xs text-gray-500">{inc.dedup_key}</td>
                        <td className="px-4 py-3 text-gray-500">{formatTs(inc.opened_at)}</td>
                        <td className="px-4 py-3 text-gray-500">{formatTs(inc.resolved_at)}</td>
                        <td className="px-4 py-3 text-right">
                          {inc.state === 'open' && (
                            <button
                              className={secondaryButtonClass}
                              onClick={() => void handleResolveIncident(inc)}
                            >
                              Resolve
                            </button>
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
      )}

      {/* ---- Alert Rules ---- */}
      {tab === 'rules' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button className={primaryButtonClass} onClick={() => setShowRuleForm((v) => !v)}>
              {showRuleForm ? 'Cancel' : '+ New rule'}
            </button>
          </div>

          {showRuleForm && (
            <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-3">
              <h3 className="font-medium text-gray-900">Create alert rule</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <Field label="Server">
                  <select
                    className={inputClass}
                    value={newRule.server_id}
                    onChange={(e) => setNewRule({ ...newRule, server_id: e.target.value })}
                  >
                    <option value="">- select server -</option>
                    {servers.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
                  </select>
                </Field>
                <Field label="Name">
                  <input className={inputClass} value={newRule.name} onChange={(e) => setNewRule({ ...newRule, name: e.target.value })} />
                </Field>
                <Field label="Metric">
                  <select className={inputClass} value={newRule.metric} onChange={(e) => setNewRule({ ...newRule, metric: e.target.value })}>
                    {['cpu_pct', 'mem_pct', 'disk_pct', 'load1'].map((m) => <option key={m}>{m}</option>)}
                  </select>
                </Field>
                <Field label="Comparator">
                  <select className={inputClass} value={newRule.comparator} onChange={(e) => setNewRule({ ...newRule, comparator: e.target.value as 'gt' | 'lt' })}>
                    <option value="gt">{'>'} gt (above)</option>
                    <option value="lt">{'<'} lt (below)</option>
                  </select>
                </Field>
                <Field label="Threshold">
                  <input type="number" className={inputClass} value={newRule.threshold} onChange={(e) => setNewRule({ ...newRule, threshold: Number(e.target.value) })} />
                </Field>
                <Field label="Duration (seconds)">
                  <input type="number" className={inputClass} value={newRule.duration_seconds} onChange={(e) => setNewRule({ ...newRule, duration_seconds: Number(e.target.value) })} />
                </Field>
                <Field label="Severity">
                  <select className={inputClass} value={newRule.severity} onChange={(e) => setNewRule({ ...newRule, severity: e.target.value as 'info' | 'warning' | 'critical' })}>
                    <option value="info">info</option>
                    <option value="warning">warning</option>
                    <option value="critical">critical</option>
                  </select>
                </Field>
              </div>
              <div className="flex gap-2">
                <button className={primaryButtonClass} onClick={() => void handleCreateRule()}>Create</button>
                <button className={secondaryButtonClass} onClick={() => setShowRuleForm(false)}>Cancel</button>
              </div>
            </div>
          )}

          {rules.length === 0 ? (
            <EmptyState title="No alert rules">Create a rule to start monitoring metric thresholds.</EmptyState>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-gray-200">
              <table className="min-w-full divide-y divide-gray-200 text-sm">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-3 text-left font-medium text-gray-500">State</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500">Name</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500">Server</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500">Condition</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500">Severity</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500">Duration</th>
                    <th className="px-4 py-3" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 bg-white">
                  {rules.map((rule) => {
                    const srv = servers.find((s) => s.id === rule.server_id);
                    return (
                      <tr key={rule.id}>
                        <td className="px-4 py-3"><StatusBadge state={ruleState(rule)} detail={rule.enabled ? 'enabled' : 'disabled'} /></td>
                        <td className="px-4 py-3 font-medium text-gray-900">{rule.name}</td>
                        <td className="px-4 py-3 text-gray-700">{srv?.name ?? rule.server_id.slice(0, 8)}</td>
                        <td className="px-4 py-3 font-mono text-xs text-gray-600">
                          {rule.metric} {rule.comparator} {rule.threshold}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`font-medium ${severityColor(rule.severity)}`}>{rule.severity}</span>
                        </td>
                        <td className="px-4 py-3 text-gray-500">{rule.duration_seconds}s</td>
                        <td className="px-4 py-3">
                          <div className="flex gap-2 justify-end">
                            <button className={secondaryButtonClass} onClick={() => void handleToggleRule(rule)}>
                              {rule.enabled ? 'Disable' : 'Enable'}
                            </button>
                            <button className="text-sm text-red-600 hover:text-red-800" onClick={() => void handleDeleteRule(rule)}>
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ---- Report Schedules ---- */}
      {tab === 'schedules' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button className={primaryButtonClass} onClick={() => setShowSchedForm((v) => !v)}>
              {showSchedForm ? 'Cancel' : '+ New schedule'}
            </button>
          </div>

          {showSchedForm && (
            <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-3">
              <h3 className="font-medium text-gray-900">Create report schedule</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <Field label="Name">
                  <input className={inputClass} value={newSched.name} onChange={(e) => setNewSched({ ...newSched, name: e.target.value })} />
                </Field>
                <Field label="Cadence">
                  <select className={inputClass} value={newSched.cadence} onChange={(e) => setNewSched({ ...newSched, cadence: e.target.value as 'daily' | 'weekly' | 'monthly' })}>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </Field>
              </div>
              <div className="flex gap-2">
                <button className={primaryButtonClass} onClick={() => void handleCreateSchedule()}>Create</button>
                <button className={secondaryButtonClass} onClick={() => setShowSchedForm(false)}>Cancel</button>
              </div>
            </div>
          )}

          {schedules.length === 0 ? (
            <EmptyState title="No report schedules">Create a schedule to receive periodic summary reports.</EmptyState>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-gray-200">
              <table className="min-w-full divide-y divide-gray-200 text-sm">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-3 text-left font-medium text-gray-500">Name</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500">Cadence</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500">Next run</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500">Last run</th>
                    <th className="px-4 py-3" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 bg-white">
                  {schedules.map((s) => (
                    <tr key={s.id}>
                      <td className="px-4 py-3 font-medium text-gray-900">{s.name}</td>
                      <td className="px-4 py-3 text-gray-700">{s.cadence}</td>
                      <td className="px-4 py-3 text-gray-500">{formatTs(s.next_run_at)}</td>
                      <td className="px-4 py-3 text-gray-500">{formatTs(s.last_run_at)}</td>
                      <td className="px-4 py-3 text-right">
                        <button className="text-sm text-red-600 hover:text-red-800" onClick={() => void handleDeleteSchedule(s)}>
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
      )}
    </div>
  );
}
