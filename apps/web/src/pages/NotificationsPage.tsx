import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { goeyToast } from 'goey-toast';
import { notifyApi, ApiError } from '../api/client';
import type { NotificationChannel, NotifyDelivery } from '../api/client';
import { ErrorNote, Modal, Field } from '../components/ui';

type Tab = 'channels' | 'inbox';

function getChannelIcon(type: string): string {
  switch (type.toLowerCase()) {
    case 'email':
      return '📧';
    case 'webhook':
      return '🔗';
    case 'slack':
      return '💬';
    case 'discord':
      return '🎮';
    case 'telegram':
      return '✈️';
    case 'in_panel':
    default:
      return '🔔';
  }
}

export function NotificationsPage() {
  const [tab, setTab] = useState<Tab>('channels');
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [inbox, setInbox] = useState<NotifyDelivery[]>([]);
  const [unread, setUnread] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | Error | null>(null);

  const [isAddChannelOpen, setIsAddChannelOpen] = useState(false);
  const [type, setType] = useState('in_panel');
  const [name, setName] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<ApiError | Error | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);

  async function loadChannels() {
    setLoading(true);
    setError(null);
    try {
      const res = await notifyApi.listChannels();
      setChannels(res.channels ?? []);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }

  async function loadInbox() {
    setLoading(true);
    setError(null);
    try {
      const [inboxRes, unreadRes] = await Promise.all([
        notifyApi.inbox(),
        notifyApi.unreadCount(),
      ]);
      setInbox(inboxRes.deliveries ?? []);
      setUnread(unreadRes.unread_count);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (tab === 'channels') void loadChannels();
    else void loadInbox();
  }, [tab]);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setSubmitting(true);
    setFormError(null);
    try {
      await notifyApi.createChannel({ type, name: name.trim(), config: {} });
      goeyToast.success('Notification channel created');
      setName('');
      setIsAddChannelOpen(false);
      void loadChannels();
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      goeyToast.error(`Failed: ${e.message}`);
      setFormError(e);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(id: string) {
    try {
      await notifyApi.deleteChannel(id);
      goeyToast.success('Channel deleted');
      void loadChannels();
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      goeyToast.error(`Failed: ${e.message}`);
      setError(e);
    }
  }

  async function handleTestSend(id: string) {
    setTestingId(id);
    try {
      await notifyApi.testChannel(id);
      goeyToast.success('Test notification enqueued');
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      goeyToast.error(`Test failed: ${e.message}`);
    } finally {
      setTestingId(null);
    }
  }

  async function handleMarkRead(id: string) {
    try {
      await notifyApi.markRead(id);
      goeyToast.success('Marked as read');
      void loadInbox();
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      setError(e);
    }
  }

  const tabs: { id: Tab; label: string; count?: number; icon: string }[] = [
    {
      id: 'channels',
      label: 'Notification Channels',
      count: channels.length,
      icon: 'M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9',
    },
    {
      id: 'inbox',
      label: 'Inbox Feed',
      count: unread,
      icon: 'M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4',
    },
  ];

  const inputClass = 'w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 transition-all';

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Notifications</h1>
          <p className="text-sm text-slate-500">Configure alert channels, webhook integrations, and review system delivery inbox.</p>
        </div>
        {tab === 'channels' && (
          <button
            type="button"
            onClick={() => setIsAddChannelOpen(true)}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all flex items-center gap-1.5 w-fit"
          >
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Add Channel
          </button>
        )}
      </div>

      {/* Tabs */}
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
              {t.id === 'inbox' && unread > 0 && (
                <span className="rounded-full bg-indigo-600 px-2 py-0.5 text-xs font-semibold text-white">
                  {unread}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {error && <ErrorNote error={error} title="Error" onRetry={() => tab === 'channels' ? void loadChannels() : void loadInbox()} />}

      {/* ─── TAB: CHANNELS ─── */}
      {tab === 'channels' && (
        <div className="space-y-6">
          <Modal isOpen={isAddChannelOpen} onClose={() => setIsAddChannelOpen(false)} title="Add Notification Channel">
            <form onSubmit={(e) => void handleCreate(e)} className="space-y-4">
              <Field label="Channel Type">
                <select
                  value={type}
                  onChange={(e) => setType(e.target.value)}
                  className={inputClass}
                >
                  <option value="in_panel">In-Panel (Dashboard Banner)</option>
                  <option value="email">Email (SMTP / SES)</option>
                  <option value="telegram">Telegram Bot</option>
                  <option value="webhook">Custom Webhook (HTTP POST)</option>
                  <option value="discord">Discord Webhook</option>
                  <option value="slack">Slack Incoming Webhook</option>
                </select>
              </Field>
              <Field label="Channel Name / Label">
                <input
                  type="text"
                  placeholder="e.g. Ops Team Slack or DevOps Alert"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className={inputClass}
                />
              </Field>
              {formError && <div className="mt-2"><ErrorNote error={formError} title="Failed to create channel" /></div>}
              <div className="flex justify-end gap-2 pt-3 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setIsAddChannelOpen(false)}
                  className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all disabled:opacity-50"
                >
                  {submitting ? 'Adding…' : 'Add Channel'}
                </button>
              </div>
            </form>
          </Modal>

          {loading ? (
            <p className="text-sm text-slate-500">Loading channels…</p>
          ) : channels.length === 0 ? (
            <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
              <span className="text-4xl mb-3 block">🔔</span>
              <h3 className="text-base font-semibold text-slate-900">No channels configured</h3>
              <p className="text-sm text-slate-500 mt-1 max-w-sm mx-auto">
                Set up email, webhook, Slack, or Discord to receive instantaneous alerts when systems trigger.
              </p>
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {channels.map((c) => {
                const icon = getChannelIcon(c.type);
                const isTesting = testingId === c.id;

                return (
                  <div
                    key={c.id}
                    className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4 hover:border-slate-300 transition-all flex flex-col justify-between"
                  >
                    <div className="space-y-3">
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-3">
                          <span className="text-2xl p-2 rounded-lg bg-slate-50 border border-slate-100">{icon}</span>
                          <div>
                            <h3 className="text-sm font-semibold text-slate-900">{c.name}</h3>
                            <span className="text-xs uppercase font-medium text-slate-400 font-mono tracking-wider">{c.type}</span>
                          </div>
                        </div>
                        <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                          c.enabled
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                            : 'bg-slate-100 text-slate-600'
                        }`}>
                          {c.enabled ? 'Active' : 'Disabled'}
                        </span>
                      </div>

                      <div className="text-xs text-slate-500 pt-1 border-t border-slate-100 flex justify-between items-center">
                        <span>Created:</span>
                        <span className="font-mono text-slate-700">{new Date(c.created_at).toLocaleDateString()}</span>
                      </div>
                    </div>

                    <div className="pt-3 border-t border-slate-100 flex items-center justify-between gap-2">
                      <button
                        type="button"
                        onClick={() => void handleTestSend(c.id)}
                        disabled={isTesting}
                        className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-all active:scale-95 disabled:opacity-50 flex items-center gap-1.5"
                      >
                        <svg className="h-3.5 w-3.5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                        </svg>
                        {isTesting ? 'Sending…' : 'Test Send'}
                      </button>

                      <button
                        type="button"
                        onClick={() => void handleDelete(c.id)}
                        className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700 transition-all active:scale-95"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ─── TAB: INBOX ─── */}
      {tab === 'inbox' && (
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
            <div className="p-5 border-b border-slate-100 flex items-center justify-between">
              <div>
                <h2 className="text-base font-semibold text-slate-900">Inbox Notification Feed</h2>
                <p className="text-xs text-slate-500 mt-0.5">Dispatched alerts and automated status deliveries.</p>
              </div>
              {unread > 0 && (
                <span className="rounded-full bg-amber-50 px-3 py-1 text-xs font-medium text-amber-700 border border-amber-200">
                  {unread} Unread
                </span>
              )}
            </div>

            {loading ? (
              <div className="p-8 text-center text-sm text-slate-500">Loading notification inbox…</div>
            ) : inbox.length === 0 ? (
              <div className="p-12 text-center">
                <span className="text-4xl mb-2 block">📭</span>
                <h3 className="text-base font-semibold text-slate-900">Inbox is empty</h3>
                <p className="text-sm text-slate-500 mt-1 max-w-sm mx-auto">No notifications have been delivered to your in-panel account yet.</p>
              </div>
            ) : (
              <ul className="divide-y divide-slate-100">
                {inbox.map((d) => {
                  const isRead = d.state === 'read';

                  return (
                    <li
                      key={d.id}
                      className={`flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 p-5 transition-colors ${
                        isRead ? 'bg-white hover:bg-slate-50/50' : 'bg-indigo-50/30 hover:bg-indigo-50/50'
                      }`}
                    >
                      <div className="flex items-start gap-3 min-w-0">
                        <span className="mt-1 flex h-2.5 w-2.5 shrink-0 rounded-full">
                          <span className={`h-2.5 w-2.5 rounded-full ${isRead ? 'bg-slate-300' : 'bg-indigo-600 animate-pulse'}`} />
                        </span>
                        <div>
                          <div className="flex items-center gap-2">
                            <p className={`text-sm font-semibold ${isRead ? 'text-slate-800' : 'text-slate-900 font-bold'}`}>
                              {d.event}
                            </p>
                            {!isRead && (
                              <span className="rounded-full bg-indigo-100 px-2 py-0.2 text-[10px] font-bold text-indigo-700 uppercase">
                                New
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-slate-400 mt-0.5 font-mono">
                            {new Date(d.created_at).toLocaleString()}
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-3 shrink-0 self-end sm:self-center">
                        {!isRead ? (
                          <button
                            type="button"
                            onClick={() => void handleMarkRead(d.id)}
                            className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-all shadow-sm active:scale-95"
                          >
                            Mark Read
                          </button>
                        ) : (
                          <span className="text-xs text-slate-400 font-medium">Read</span>
                        )}
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
