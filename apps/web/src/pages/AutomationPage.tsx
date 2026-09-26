import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { automationApi, ApiError } from '../api/client';
import type { AutomationRule, OutboundWebhook, WebhookDelivery } from '../api/client';
import { ErrorNote, EmptyState, Modal, Field, inputClass, primaryButtonClass, secondaryButtonClass } from '../components/ui';

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
      void loadRules();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setRuleSubmitting(false);
    }
  }

  async function handleToggleRule(rule: AutomationRule) {
    try {
      await automationApi.updateRule(rule.id, { enabled: !rule.enabled });
      void loadRules();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  }

  async function handleDeleteRule(id: string) {
    try {
      await automationApi.deleteRule(id);
      void loadRules();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  }

  async function handleTestRule(id: string) {
    try {
      const res = await automationApi.testRule(id);
      alert(`Simulation result: Trigger matched! Action that would execute: ${res.would_action}`);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
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
      void loadWebhooks();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setWebhookSubmitting(false);
    }
  }

  async function handleDeleteWebhook(id: string) {
    try {
      await automationApi.deleteWebhook(id);
      void loadWebhooks();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  }

  async function handleTestWebhook(id: string) {
    try {
      const res = await automationApi.testWebhook(id);
      alert(`Test ping enqueued for ${res.target_url} (Delivery ID: ${res.delivery_id})`);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  }

  const tabCls = (t: Tab) =>
    `px-4 py-2 text-sm font-medium border-b-2 ${
      tab === t
        ? 'border-accent text-ink'
        : 'border-transparent text-ink-secondary hover:text-ink'
    }`;

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-ink">Automation & Webhooks</h1>
        <p className="text-sm text-ink-secondary mt-1">
          Automated event-condition-action policies and signed outbound webhook delivery.
        </p>
      </div>

      <div className="flex border-b border-border">
        <button className={tabCls('rules')} onClick={() => setTab('rules')}>Automation Rules</button>
        <button className={tabCls('webhooks')} onClick={() => setTab('webhooks')}>Outbound Webhooks</button>
      </div>

      {error && <ErrorNote error={error} title="Error" onRetry={() => tab === 'rules' ? void loadRules() : void loadWebhooks()} />}

      {tab === 'rules' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-medium text-ink">Configured Rules</h2>
            <button
              type="button"
              onClick={() => setIsRuleOpen(true)}
              className={primaryButtonClass}
            >
              + Create Rule
            </button>
          </div>

          <Modal isOpen={isRuleOpen} onClose={() => setIsRuleOpen(false)} title="Create Automation Rule">
            <form onSubmit={(e) => void handleCreateRule(e)} className="space-y-4">
              <Field label="Rule Name">
                <input
                  type="text"
                  placeholder="Rule name (e.g. Disk pressure alert)"
                  required
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  className={inputClass}
                />
              </Field>
              <Field label="Trigger Event">
                <select
                  value={triggerEvent}
                  onChange={(e) => setTriggerEvent(e.target.value)}
                  className={inputClass}
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
                  className={inputClass}
                >
                  <option value="notify">THEN notify</option>
                  <option value="incident_open">THEN open incident</option>
                  <option value="job_postpone">THEN postpone non-critical jobs</option>
                  <option value="service_restart">THEN restart service</option>
                </select>
              </Field>
              <div className="flex justify-end gap-2 pt-2">
                <button type="button" onClick={() => setIsRuleOpen(false)} className={secondaryButtonClass}>Cancel</button>
                <button
                  type="submit"
                  disabled={ruleSubmitting}
                  className={primaryButtonClass}
                >
                  {ruleSubmitting ? 'Creating…' : 'Create Rule'}
                </button>
              </div>
            </form>
          </Modal>
          <section>
            {loading ? (
              <p className="text-sm text-ink-secondary">Loading…</p>
            ) : rules.length === 0 ? (
              <EmptyState title="No automation rules">Create your first automated action policy above.</EmptyState>
            ) : (
              <div className="overflow-x-auto rounded-lg border border-border">
                <table className="w-full text-sm">
                  <thead className="bg-elevated text-ink-secondary">
                    <tr>
                      <th className="px-4 py-2 text-left font-medium">Name</th>
                      <th className="px-4 py-2 text-left font-medium">Trigger</th>
                      <th className="px-4 py-2 text-left font-medium">Action</th>
                      <th className="px-4 py-2 text-left font-medium">State</th>
                      <th className="px-4 py-2 text-left font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {rules.map((r) => (
                      <tr key={r.id} className="bg-surface hover:bg-elevated/50">
                        <td className="px-4 py-2 font-medium text-ink">{r.name}</td>
                        <td className="px-4 py-2 font-mono text-xs text-ink-secondary">{r.trigger_event}</td>
                        <td className="px-4 py-2 text-xs text-ink-secondary">{r.action_type}</td>
                        <td className="px-4 py-2">
                          <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${
                            r.enabled ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'
                          }`}>
                            {r.enabled ? 'enabled' : 'disabled'}
                          </span>
                        </td>
                        <td className="px-4 py-2 flex items-center gap-2">
                          <button onClick={() => void handleTestRule(r.id)} className={secondaryButtonClass}>Simulate</button>
                          <button onClick={() => void handleToggleRule(r)} className={secondaryButtonClass}>
                            {r.enabled ? 'Disable' : 'Enable'}
                          </button>
                          <button onClick={() => void handleDeleteRule(r.id)} className={secondaryButtonClass}>Delete</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      )}

      {tab === 'webhooks' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-medium text-ink">Registered Endpoints</h2>
            <button
              type="button"
              onClick={() => setIsWebhookOpen(true)}
              className={primaryButtonClass}
            >
              + Register Webhook
            </button>
          </div>

          <Modal isOpen={isWebhookOpen} onClose={() => setIsWebhookOpen(false)} title="Register Outbound Webhook">
            <form onSubmit={(e) => void handleCreateWebhook(e)} className="space-y-4">
              <Field label="Webhook Name">
                <input
                  type="text"
                  placeholder="Webhook name"
                  required
                  value={webhookName}
                  onChange={(e) => setWebhookName(e.target.value)}
                  className={inputClass}
                />
              </Field>
              <Field label="Target URL">
                <input
                  type="url"
                  placeholder="https://api.example.com/webhooks/receiver"
                  required
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className={inputClass}
                />
              </Field>
              <div className="flex justify-end gap-2 pt-2">
                <button type="button" onClick={() => setIsWebhookOpen(false)} className={secondaryButtonClass}>Cancel</button>
                <button
                  type="submit"
                  disabled={webhookSubmitting}
                  className={primaryButtonClass}
                >
                  {webhookSubmitting ? 'Registering…' : 'Register Webhook'}
                </button>
              </div>
            </form>
          </Modal>

          {createdSecret && (
            <div className="rounded-md border border-yellow-200 bg-yellow-50 p-4 dark:border-yellow-900/50 dark:bg-yellow-950/20">
              <p className="text-xs font-semibold text-yellow-800 dark:text-yellow-400">
                Save this HMAC-SHA256 Signing Secret (shown once):
              </p>
              <p className="mt-1 font-mono text-xs text-yellow-900 dark:text-yellow-300 break-all select-all">
                {createdSecret}
              </p>
              <p className="mt-1 text-xs text-yellow-700 dark:text-yellow-500">
                Payloads are signed via HMAC-SHA256 in the <code className="font-mono">X-Jawaker-Signature</code> HTTP header.
              </p>
            </div>
          )}

          <section>
            {loading ? (
              <p className="text-sm text-ink-secondary">Loading…</p>
            ) : webhooks.length === 0 ? (
              <EmptyState title="No webhooks registered">Outbound event webhooks allow remote systems to react to panel events.</EmptyState>
            ) : (
              <div className="overflow-x-auto rounded-lg border border-border">
                <table className="w-full text-sm">
                  <thead className="bg-elevated text-ink-secondary">
                    <tr>
                      <th className="px-4 py-2 text-left font-medium">Name</th>
                      <th className="px-4 py-2 text-left font-medium">Target URL</th>
                      <th className="px-4 py-2 text-left font-medium">State</th>
                      <th className="px-4 py-2 text-left font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {webhooks.map((w) => (
                      <tr key={w.id} className="bg-surface hover:bg-elevated/50">
                        <td className="px-4 py-2 font-medium text-ink">{w.name}</td>
                        <td className="px-4 py-2 font-mono text-xs text-ink-secondary truncate max-w-xs">{w.target_url}</td>
                        <td className="px-4 py-2">
                          <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${
                            w.enabled ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'
                          }`}>
                            {w.enabled ? 'active' : 'disabled'}
                          </span>
                        </td>
                        <td className="px-4 py-2 flex items-center gap-2">
                          <button onClick={() => void handleTestWebhook(w.id)} className={secondaryButtonClass}>Test Ping</button>
                          <button onClick={() => void loadDeliveries(w.id)} className={secondaryButtonClass}>History</button>
                          <button onClick={() => void handleDeleteWebhook(w.id)} className={secondaryButtonClass}>Delete</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {selectedWebhook && (
            <section className="space-y-3">
              <h2 className="text-base font-medium text-ink">Delivery History & DLQ ({deliveries.length})</h2>
              {deliveries.length === 0 ? (
                <p className="text-xs text-ink-secondary">No deliveries recorded for this endpoint yet.</p>
              ) : (
                <div className="overflow-x-auto rounded-lg border border-border">
                  <table className="w-full text-xs">
                    <thead className="bg-elevated text-ink-secondary">
                      <tr>
                        <th className="px-3 py-2 text-left">Event</th>
                        <th className="px-3 py-2 text-left">Status</th>
                        <th className="px-3 py-2 text-left">HTTP Code</th>
                        <th className="px-3 py-2 text-left">Attempts</th>
                        <th className="px-3 py-2 text-left">Created</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {deliveries.map((d) => (
                        <tr key={d.id} className="bg-surface">
                          <td className="px-3 py-2 font-mono text-ink">{d.event}</td>
                          <td className="px-3 py-2">
                            <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${
                              d.status === 'delivered' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' :
                              d.status === 'failed' || d.status === 'dead_letter' ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400' :
                              'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                            }`}>
                              {d.status}
                            </span>
                          </td>
                          <td className="px-3 py-2 font-mono text-ink-secondary">{d.status_code ?? '-'}</td>
                          <td className="px-3 py-2 text-ink-secondary">{d.attempt_count}/{d.max_attempts}</td>
                          <td className="px-3 py-2 text-ink-secondary">{new Date(d.created_at).toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}
        </div>
      )}
    </div>
  );
}
