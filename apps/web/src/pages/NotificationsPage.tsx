import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { notifyApi, ApiError } from '../api/client';
import type { NotificationChannel, NotifyDelivery } from '../api/client';
import { ErrorNote, EmptyState, Modal, Field, inputClass, primaryButtonClass, secondaryButtonClass } from '../components/ui';

type Tab = 'channels' | 'inbox';

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
      setName('');
      setIsAddChannelOpen(false);
      void loadChannels();
    } catch (err) {
      setFormError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(id: string) {
    try {
      await notifyApi.deleteChannel(id);
      void loadChannels();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  }

  async function handleMarkRead(id: string) {
    try {
      await notifyApi.markRead(id);
      void loadInbox();
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
        <h1 className="text-2xl font-semibold text-ink">Notifications</h1>
        <p className="text-sm text-ink-secondary mt-1">Manage channels and your notification inbox.</p>
      </div>

      <div className="flex border-b border-border">
        <button className={tabCls('channels')} onClick={() => setTab('channels')}>Channels</button>
        <button className={tabCls('inbox')} onClick={() => setTab('inbox')}>
          Inbox {unread > 0 && <span className="ml-1 rounded-full bg-accent px-1.5 text-xs text-white">{unread}</span>}
        </button>
      </div>

      {error && <ErrorNote error={error} title="Error" onRetry={() => tab === 'channels' ? void loadChannels() : void loadInbox()} />}

      {tab === 'channels' && (
        <>
          <div className="flex items-center justify-between">
            <h2 className="text-base font-medium text-ink">Channels</h2>
            <button
              type="button"
              onClick={() => setIsAddChannelOpen(true)}
              className={primaryButtonClass}
            >
              + Add Channel
            </button>
          </div>

          <Modal isOpen={isAddChannelOpen} onClose={() => setIsAddChannelOpen(false)} title="Add Notification Channel">
            <form onSubmit={(e) => void handleCreate(e)} className="space-y-4">
              <Field label="Type">
                <select
                  value={type}
                  onChange={(e) => setType(e.target.value)}
                  className={inputClass}
                >
                  <option value="in_panel">In-panel</option>
                  <option value="email">Email</option>
                  <option value="telegram">Telegram</option>
                  <option value="webhook">Webhook</option>
                  <option value="discord">Discord</option>
                  <option value="slack">Slack</option>
                </select>
              </Field>
              <Field label="Channel Name">
                <input
                  type="text"
                  placeholder="Channel name"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className={inputClass}
                />
              </Field>
              {formError && <div className="mt-2"><ErrorNote error={formError} title="Failed to create channel" /></div>}
              <div className="flex justify-end gap-2 pt-2">
                <button type="button" onClick={() => setIsAddChannelOpen(false)} className={secondaryButtonClass}>Cancel</button>
                <button
                  type="submit"
                  disabled={submitting}
                  className={primaryButtonClass}
                >
                  {submitting ? 'Adding…' : 'Add Channel'}
                </button>
              </div>
            </form>
          </Modal>

          <section>
            {loading ? (
              <p className="text-sm text-ink-secondary">Loading…</p>
            ) : channels.length === 0 ? (
              <EmptyState title="No channels">No notification channels configured.</EmptyState>
            ) : (
              <div className="overflow-x-auto rounded-lg border border-border">
                <table className="w-full text-sm">
                  <thead className="bg-elevated text-ink-secondary">
                    <tr>
                      <th className="px-4 py-2 text-left font-medium">Name</th>
                      <th className="px-4 py-2 text-left font-medium">Type</th>
                      <th className="px-4 py-2 text-left font-medium">Enabled</th>
                      <th className="px-4 py-2 text-left font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {channels.map((c) => (
                      <tr key={c.id} className="bg-surface hover:bg-elevated/50">
                        <td className="px-4 py-2 text-ink">{c.name}</td>
                        <td className="px-4 py-2 text-ink-secondary">{c.type}</td>
                        <td className="px-4 py-2">
                          <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${c.enabled ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'}`}>
                            {c.enabled ? 'enabled' : 'disabled'}
                          </span>
                        </td>
                        <td className="px-4 py-2">
                          <button onClick={() => void handleDelete(c.id)} className={secondaryButtonClass}>Delete</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}

      {tab === 'inbox' && (
        <section>
          {loading ? (
            <p className="text-sm text-ink-secondary">Loading…</p>
          ) : inbox.length === 0 ? (
            <EmptyState title="Inbox empty">No notifications delivered yet.</EmptyState>
          ) : (
            <div className="space-y-2">
              {inbox.map((d) => (
                <div key={d.id} className="flex items-start justify-between rounded-lg border border-border bg-surface p-4">
                  <div>
                    <p className="text-sm font-medium text-ink">{d.event}</p>
                    <p className="text-xs text-ink-secondary mt-0.5">{new Date(d.created_at).toLocaleString()}</p>
                  </div>
                  <button onClick={() => void handleMarkRead(d.id)} className={secondaryButtonClass}>Mark read</button>
                </div>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
