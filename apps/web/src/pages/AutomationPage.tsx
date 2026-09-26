import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { goeyToast } from 'goey-toast';
import { automationApi, ApiError } from '../api/client';
import type { AutomationRule, OutboundWebhook, WebhookDelivery } from '../api/client';
import { ErrorNote, Modal, Field } from '../components/ui';

type Tab = 'rules' | 'webhooks';

export function AutomationPage() {
  const [tab, setTab] = useState<Tab>('rules');
  const [rules, setRules] = useState<AutomationRule[]>([]);
  const [webhooks, setWebhooks] = useState<OutboundWebhook[]>([]);
  const [selectedWebhook, setSelectedWebhook] = useState<string | null>(null);
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | Error | null>(null);

  // New Rule State
  const [isRuleOpen, setIsRuleOpen] = useState(false);
  const [ruleName, setRuleName] = useState('');
  const [triggerEvent, setTriggerEvent] = useState('disk.pressure');
  const [actionType, setActionType] = useState('notify');
  const [ruleSubmitting, setRuleSubmitting] = useState(false);

  // New Webhook State
  const [isWebhookOpen, setIsWebhookOpen] = useState(false);
  const [webhookName, setWebhookName] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);
  const [webhookSubmitting, setWebhookSubmitting] = useState(false);

  async function loadRules() {
    setLoading(true);
    setError(null);
    try {
      const res = await automationApi.listRules();
      setRules(res.rules ?? []);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }

  async function loadWebhooks() {
    setLoading(true);
    setError(null);
    try {
      const res = await automationApi.listWebhooks();
      setWebhooks(res.webhooks ?? []);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }

  async function loadDeliveries(webhookId: string) {
    setSelectedWebhook(webhookId);
    try {
      const res = await automationApi.getDeliveries(webhookId);
      setDeliveries(res.deliveries ?? []);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  }

  useEffect(() => {
    if (tab === 'rules') void loadRules();
    else void loadWebhooks();
  }, [tab]);

  async function handleCreateRule(e: FormEvent) {
    e.preventDefault();
    if (!ruleName.trim()) return;
    setRuleSubmitting(true);
    try {
      await automationApi.createRule({
        name: ruleName.trim(),
        trigger_event: triggerEvent,
        action_type: actionType,
        condition: { field: 'threshold', value: 90 },
      });
      setRuleName('');
      setIsRuleOpen(false);
      goeyToast.success('Automation rule created');
      void loadRules();
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      setError(e);
      goeyToast.error(`Failed to create rule: ${e.message}`);
    } finally {
      setRuleSubmitting(false);
    }
  }

  async function handleToggleRule(rule: AutomationRule) {
    try {
      await automationApi.updateRule(rule.id, { enabled: !rule.enabled });
      goeyToast.success(`Rule ${rule.enabled ? 'disabled' : 'enabled'}`);
      void loadRules();
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      setError(e);
      goeyToast.error(`Failed to update rule: ${e.message}`);
    }
  }

  async function handleDeleteRule(id: string) {
    try {
      await automationApi.deleteRule(id);
      goeyToast.success('Rule deleted');
      void loadRules();
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      setError(e);
      goeyToast.error(`Failed to delete rule: ${e.message}`);
    }
  }

  async function handleTestRule(id: string) {
    try {
      const res = await automationApi.testRule(id);
      goeyToast.info(`Simulation result: Trigger matched! Action: ${res.would_action}`);
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      setError(e);
      goeyToast.error(`Rule simulation failed: ${e.message}`);
    }
  }

  async function handleCreateWebhook(e: FormEvent) {
    e.preventDefault();
    if (!webhookName.trim() || !targetUrl.trim()) return;
    setWebhookSubmitting(true);
    try {
      const res = await automationApi.createWebhook({
        name: webhookName.trim(),
        target_url: targetUrl.trim(),
      });
      setCreatedSecret(res.signing_secret);
      setWebhookName('');
      setTargetUrl('');
      setIsWebhookOpen(false);
      goeyToast.success('Outbound webhook registered');
      void loadWebhooks();
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      setError(e);
      goeyToast.error(`Failed to register webhook: ${e.message}`);
    } finally {
      setWebhookSubmitting(false);
    }
  }

  async function handleDeleteWebhook(id: string) {
    try {
      await automationApi.deleteWebhook(id);
      goeyToast.success('Webhook deleted');
      void loadWebhooks();
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      setError(e);
      goeyToast.error(`Failed to delete webhook: ${e.message}`);
    }
  }

  async function handleTestWebhook(id: string) {
    try {
      const res = await automationApi.testWebhook(id);
      goeyToast.info(`Test ping enqueued for ${res.target_url} (Delivery ID: ${res.delivery_id})`);
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      setError(e);
      goeyToast.error(`Webhook test ping failed: ${e.message}`);
    }
  }

  const inputCls = 'block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none';
  const btnPrimary = 'rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all';
  const btnSecondary = 'rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all';
  const btnSmSecondary = 'rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-all';
  const btnSmDanger = 'rounded-lg bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700 transition-all';
  const tabCls = (t: Tab) =>
    `pb-2 text-sm font-medium border-b-2 transition-all ${
      tab === t
        ? 'border-indigo-600 text-indigo-600'
        : 'border-transparent text-slate-500 hover:text-slate-800'
    }`;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Automation & Webhooks</h1>
          <p className="text-sm text-slate-500">Automated event-condition-action policies and signed outbound webhook delivery.</p>
        </div>
        <div className="mt-2 sm:mt-0">
          {tab === 'rules' ? (
            <button
              type="button"
              onClick={() => setIsRuleOpen(true)}
              className={btnPrimary}
            >
              + Create Rule
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setIsWebhookOpen(true)}
              className={btnPrimary}
            >
              + Register Webhook
            </button>
          )}
        </div>
      </div>

      <div className="flex border-b border-slate-200 gap-4">
        <button className={tabCls('rules')} onClick={() => setTab('rules')}>Automation Rules</button>
        <button className={tabCls('webhooks')} onClick={() => setTab('webhooks')}>Outbound Webhooks</button>
      </div>

      {error && <ErrorNote error={error} title="Error" onRetry={() => tab === 'rules' ? void loadRules() : void loadWebhooks()} />}

      {tab === 'rules' && (
        <div className="space-y-6">
          <Modal isOpen={isRuleOpen} onClose={() => setIsRuleOpen(false)} title="Create Automation Rule">
            <form onSubmit={(e) => void handleCreateRule(e)} className="space-y-4">
              <Field label="Rule Name">
                <input
                  type="text"
                  placeholder="Rule name (e.g. Disk pressure alert)"
                  required
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  className={inputCls}
                />
              </Field>
              <Field label="Trigger Event">
                <select
                  value={triggerEvent}
                  onChange={(e) => setTriggerEvent(e.target.value)}
                  className={inputCls}
                >
                  <option value="disk.pressure">WHEN disk.pressure (&gt;90%)</option>
                  <option value="backup.failed">WHEN backup.failed</option>
                  <option value="deployment.failed">WHEN deployment.failed</option>
                  <option value="server.offline">WHEN server.offline</option>
                  <option value="security.alert">WHEN security.alert</option>
                </select>
              </Field>
              <Field label="Action">
                <select
                  value={actionType}
                  onChange={(e) => setActionType(e.target.value)}
                  className={inputCls}
                >
                  <option value="notify">THEN notify</option>
                  <option value="incident_open">THEN open incident</option>
                  <option value="job_postpone">THEN postpone non-critical jobs</option>
                  <option value="service_restart">THEN restart service</option>
                </select>
              </Field>
              <div className="flex justify-end gap-2 pt-2">
                <button type="button" onClick={() => setIsRuleOpen(false)} className={btnSecondary}>Cancel</button>
                <button
                  type="submit"
                  disabled={ruleSubmitting}
                  className={btnPrimary}
                >
                  {ruleSubmitting ? 'Creating?' : 'Create Rule'}
                </button>
              </div>
            </form>
          </Modal>

          <section>
            {loading ? (
              <p className="text-sm text-slate-500">Loading?</p>
            ) : rules.length === 0 ? (
              <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
                <div className="text-4xl mb-3">?</div>
                <h3 className="text-base font-semibold text-slate-900">No automation rules</h3>
                <p className="text-sm text-slate-500 mt-1">Create your first automated action policy above.</p>
              </div>
            ) : (
              <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="border-b border-slate-200">
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Name</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Trigger</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Action</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">State</th>
                        <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {rules.map((r) => (
                        <tr key={r.id} className="hover:bg-slate-50/50 transition-colors">
                          <td className="px-4 py-3 text-sm font-medium text-slate-900">{r.name}</td>
                          <td className="px-4 py-3 text-sm">
                            <span className="rounded-full px-2.5 py-0.5 text-xs font-mono font-medium bg-amber-50 text-amber-700 border border-amber-200">
                              {r.trigger_event}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-sm">
                            <span className="rounded-full px-2.5 py-0.5 text-xs font-mono font-medium bg-blue-50 text-blue-700 border border-blue-200">
                              {r.action_type}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-sm">
                            <button
                              type="button"
                              onClick={() => void handleToggleRule(r)}
                              className={`rounded-full px-2.5 py-0.5 text-xs font-medium transition-all ${
                                r.enabled
                                  ? 'bg-emerald-50 text-emerald-700 border border-emerald-200 hover:bg-emerald-100'
                                  : 'bg-slate-100 text-slate-600 border border-slate-200 hover:bg-slate-200'
                              }`}
                            >
                              {r.enabled ? 'Enabled' : 'Disabled'}
                            </button>
                          </td>
                          <td className="px-4 py-3 text-sm text-right">
                            <div className="flex items-center justify-end gap-2">
                              <button onClick={() => void handleTestRule(r.id)} className={btnSmSecondary}>Simulate</button>
                              <button onClick={() => void handleDeleteRule(r.id)} className={btnSmDanger}>Delete</button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </section>
        </div>
      )}

      {tab === 'webhooks' && (
        <div className="space-y-6">
          <Modal isOpen={isWebhookOpen} onClose={() => setIsWebhookOpen(false)} title="Register Outbound Webhook">
            <form onSubmit={(e) => void handleCreateWebhook(e)} className="space-y-4">
              <Field label="Webhook Name">
                <input
                  type="text"
                  placeholder="Webhook name"
                  required
                  value={webhookName}
                  onChange={(e) => setWebhookName(e.target.value)}
                  className={inputCls}
                />
              </Field>
              <Field label="Target URL">
                <input
                  type="url"
                  placeholder="https://api.example.com/webhooks/receiver"
                  required
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className={inputCls}
                />
              </Field>
              <div className="flex justify-end gap-2 pt-2">
                <button type="button" onClick={() => setIsWebhookOpen(false)} className={btnSecondary}>Cancel</button>
                <button
                  type="submit"
                  disabled={webhookSubmitting}
                  className={btnPrimary}
                >
                  {webhookSubmitting ? 'Registering?' : 'Register Webhook'}
                </button>
              </div>
            </form>
          </Modal>

          {createdSecret && (
            <div className="rounded-xl border border-amber-200 bg-amber-50 p-4">
              <p className="text-xs font-semibold text-amber-800">
                Save this HMAC-SHA256 Signing Secret (shown once):
              </p>
              <p className="mt-1 font-mono text-xs text-amber-900 break-all select-all">
                {createdSecret}
              </p>
              <p className="mt-1 text-xs text-amber-700">
                Payloads are signed via HMAC-SHA256 in the <code className="font-mono">X-Jawaker-Signature</code> HTTP header.
              </p>
            </div>
          )}

          <section>
            {loading ? (
              <p className="text-sm text-slate-500">Loading?</p>
            ) : webhooks.length === 0 ? (
              <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
                <div className="text-4xl mb-3">??</div>
                <h3 className="text-base font-semibold text-slate-900">No webhooks registered</h3>
                <p className="text-sm text-slate-500 mt-1">Outbound event webhooks allow remote systems to react to panel events.</p>
              </div>
            ) : (
              <div className="grid gap-4 sm:grid-cols-2">
                {webhooks.map((w) => (
                  <div key={w.id} className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between space-y-4">
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <h3 className="text-base font-semibold text-slate-900">{w.name}</h3>
                        <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                          w.enabled ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' : 'bg-slate-100 text-slate-600 border border-slate-200'
                        }`}>
                          {w.enabled ? 'Active' : 'Disabled'}
                        </span>
                      </div>
                      <div className="font-mono text-xs text-slate-500 truncate" title={w.target_url}>
                        {w.target_url}
                      </div>
                      <div className="flex flex-wrap gap-1 pt-1">
                        <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-indigo-50 text-indigo-700 border border-indigo-200">
                          JSON payload
                        </span>
                        <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-slate-50 text-slate-600 border border-slate-200">
                          HMAC-SHA256
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100">
                      <button onClick={() => void handleTestWebhook(w.id)} className={btnSmSecondary}>Test Ping</button>
                      <button
                        onClick={() => void loadDeliveries(w.id)}
                        className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-all ${
                          selectedWebhook === w.id
                            ? 'bg-indigo-50 border-indigo-300 text-indigo-700'
                            : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
                        }`}
                      >
                        History
                      </button>
                      <button onClick={() => void handleDeleteWebhook(w.id)} className={btnSmDanger}>Delete</button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          {selectedWebhook && (
            <section className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-base font-semibold text-slate-900">Delivery History & DLQ ({deliveries.length})</h2>
                <button type="button" onClick={() => setSelectedWebhook(null)} className="text-xs text-slate-500 hover:text-slate-700">Close history</button>
              </div>
              {deliveries.length === 0 ? (
                <div className="rounded-xl border border-slate-200 bg-white p-6 text-center shadow-sm">
                  <p className="text-sm text-slate-500">No deliveries recorded for this endpoint yet.</p>
                </div>
              ) : (
                <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left">
                      <thead>
                        <tr className="border-b border-slate-200">
                          <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Event</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Status</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">HTTP Code</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Attempts</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Created</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {deliveries.map((d) => (
                          <tr key={d.id} className="hover:bg-slate-50/50">
                            <td className="px-4 py-3 text-sm font-mono text-slate-800">{d.event}</td>
                            <td className="px-4 py-3 text-sm">
                              <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                                d.status === 'delivered' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                                d.status === 'failed' || d.status === 'dead_letter' ? 'bg-red-50 text-red-700 border border-red-200' :
                                'bg-amber-50 text-amber-700 border border-amber-200'
                              }`}>
                                {d.status}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-sm font-mono text-slate-600">{d.status_code ?? '-'}</td>
                            <td className="px-4 py-3 text-sm text-slate-600">{d.attempt_count}/{d.max_attempts}</td>
                            <td className="px-4 py-3 text-sm text-slate-500">{new Date(d.created_at).toLocaleString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </section>
          )}
        </div>
      )}
    </div>
  );
}
