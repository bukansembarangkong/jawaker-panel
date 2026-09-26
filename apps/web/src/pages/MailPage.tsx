import { useEffect, useCallback, useState } from 'react';
import { goeyToast } from 'goey-toast';
import {
  type OperationalState,
  EmptyState,
  ErrorNote,
  StatusBadge,
  ConfirmModal,
  Modal,
  Field,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
} from '../components/ui';
import {
  type MailAlias,
  type MailDomain,
  type MailMailbox,
  type MailQueueEntry,
  mailApi,
  api,
} from '../api/client';
import { useFirstProjectId } from '../hooks/useFirstProjectId';

type Tab = 'domains' | 'mailboxes' | 'aliases' | 'queue';

function domainState(state: string): OperationalState {
  const map: Record<string, OperationalState> = {
    pending: 'Pending',
    active: 'Healthy',
    error: 'Failed',
    disabled: 'Disabled',
  };
  return map[state] ?? 'Unknown';
}

function StateBadge({ state }: { state: string }) {
  return <StatusBadge state={domainState(state)} detail={state} />;
}

// ── Domains tab ────────────────────────────────────────────────────────────────

function DomainsTab() {
  const projectId = useFirstProjectId();
  const [domains, setDomains] = useState<MailDomain[]>([]);
  const [servers, setServers] = useState<Array<{ id: string; name: string }>>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [adding, setAdding] = useState(false);
  const [newDomain, setNewDomain] = useState('');
  const [newServer, setNewServer] = useState('');
  const [saving, setSaving] = useState(false);
  const [confirmState, setConfirmState] = useState<{ open: boolean; message: string; onConfirm: () => void }>({ open: false, message: '', onConfirm: () => {} });

  const loadServers = useCallback(async () => {
    try {
      const page = await api.listServers();
      const list = page.servers.map((s) => ({ id: s.id, name: s.name }));
      setServers(list);
      if (list.length > 0 && !newServer) {
        setNewServer(list[0].id);
      }
    } catch {
      // Ignore: server dropdown degrades gracefully
    }
  }, [newServer]);

  const load = useCallback(() => {
    if (!projectId) return;
    setLoading(true);
    mailApi
      .listDomains(projectId)
      .then((r) => setDomains(r.domains ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, [projectId]);

  useEffect(() => {
    void loadServers();
    load();
  }, [load, loadServers]);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!projectId || !newDomain.trim() || !newServer.trim()) return;
    setSaving(true);
    try {
      await mailApi.createDomain(projectId, newServer.trim(), newDomain.trim());
      goeyToast.success('Mail domain created');
      setAdding(false);
      setNewDomain('');
      load();
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      goeyToast.error(`Failed to create domain: ${err.message}`);
      setError(err);
    } finally {
      setSaving(false);
    }
  };

  const deleteDomain = async (id: string) => {
    if (!projectId) return;
    setConfirmState({
      open: true,
      message: 'Delete this mail domain? All mailboxes and aliases will be removed. This cannot be undone.',
      onConfirm: async () => {
        try {
          await mailApi.deleteDomain(projectId, id);
          goeyToast.success('Mail domain deleted');
          load();
        } catch (e) {
          const err = e instanceof Error ? e : new Error(String(e));
          goeyToast.error(`Failed to delete domain: ${err.message}`);
          setError(err);
        }
      },
    });
  };

  const getServerName = (serverId: string) => {
    return servers.find((s) => s.id === serverId)?.name || 'Primary Node';
  };

  if (!projectId || loading) return <p className="text-ink-secondary text-sm">Loading domains...</p>;
  if (error) return <ErrorNote error={error} title="Failed to load mail domains" onRetry={load} />;

  return (
    <div className="space-y-4">
      <ConfirmModal
        isOpen={confirmState.open}
        onClose={() => setConfirmState((s) => ({ ...s, open: false }))}
        onConfirm={confirmState.onConfirm}
        title="Are you sure?"
        message={confirmState.message}
        confirmLabel="Yes, proceed"
        danger
      />

      {/* Add Domain Modal */}
      <Modal isOpen={adding} onClose={() => setAdding(false)} title="Add Mail Domain">
        <form onSubmit={create} className="space-y-4">
          <Field label="Mail Domain Name" hint="Domain for receiving and sending emails.">
            <input
              type="text"
              required
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="mail.example.com"
              className={inputClass}
            />
          </Field>

          {servers.length > 1 && (
            <Field label="Host Server" hint="Select which node hosts the mail service for this domain.">
              <select
                className={inputClass}
                value={newServer}
                onChange={(e) => setNewServer(e.target.value)}
                required
              >
                {servers.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </Field>
          )}

          <div className="flex gap-2 justify-end pt-2">
            <button
              type="button"
              onClick={() => {
                setAdding(false);
                setNewDomain('');
              }}
              className={secondaryButtonClass}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !newDomain.trim()}
              className={primaryButtonClass}
            >
              {saving ? 'Adding...' : 'Add Domain'}
            </button>
          </div>
        </form>
      </Modal>

      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-ink">Mail Domains ({domains.length})</h2>
          <p className="text-xs text-ink-muted">Configure domains to receive and route incoming and outgoing emails.</p>
        </div>
        <button
          type="button"
          onClick={() => {
            if (servers.length > 0 && !newServer) {
              setNewServer(servers[0].id);
            }
            setAdding(true);
          }}
          className={primaryButtonClass}
        >
          + Add Domain
        </button>
      </div>

      {domains.length === 0 ? (
        <EmptyState title="No mail domains configured">
          <p className="text-sm text-ink-secondary">Add your first mail domain to configure mailboxes and aliases.</p>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-lg border border-line bg-surface">
          {domains.map((d) => (
            <li key={d.id} className="flex items-center justify-between gap-4 px-4 py-3">
              <div className="min-w-0">
                <p className="truncate font-mono text-sm font-medium text-ink">{d.domain}</p>
                <p className="text-xs text-ink-muted">Host: {getServerName(d.server_id)}</p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <StateBadge state={d.state} />
                <button
                  type="button"
                  onClick={() => void deleteDomain(d.id)}
                  className="text-xs text-danger hover:underline"
                >
                  Delete
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── Mailboxes tab ──────────────────────────────────────────────────────────────

function MailboxesTab() {
  const projectId = useFirstProjectId();
  const [domains, setDomains] = useState<MailDomain[]>([]);
  const [selectedDomain, setSelectedDomain] = useState('');
  const [mailboxes, setMailboxes] = useState<MailMailbox[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [confirmState, setConfirmState] = useState<{ open: boolean; message: string; onConfirm: () => void }>({ open: false, message: '', onConfirm: () => {} });

  useEffect(() => {
    if (!projectId) return;
    mailApi
      .listDomains(projectId)
      .then((r) => {
        const ds = r.domains ?? [];
        setDomains(ds);
        if (ds.length > 0) setSelectedDomain(ds[0].id);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))));
  }, [projectId]);

  useEffect(() => {
    if (!projectId || !selectedDomain) return;
    setLoading(true);
    mailApi
      .listMailboxes(projectId, selectedDomain)
      .then((r) => setMailboxes(r.mailboxes ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, [projectId, selectedDomain]);

  const deleteMailbox = async (id: string) => {
    if (!projectId) return;
    setConfirmState({
      open: true,
      message: 'Delete this mailbox?',
      onConfirm: async () => {
        try {
          await mailApi.deleteMailbox(projectId, selectedDomain, id);
          goeyToast.success('Mailbox deleted');
          setMailboxes((prev) => prev.filter((m) => m.id !== id));
        } catch (e) {
          const err = e instanceof Error ? e : new Error(String(e));
          goeyToast.error(`Failed to delete mailbox: ${err.message}`);
          setError(err);
        }
      },
    });
  };

  if (error) return <ErrorNote error={error} title="Failed to load mailboxes" onRetry={() => setError(null)} />;

  return (
    <div className="space-y-4">
      <ConfirmModal
        isOpen={confirmState.open}
        onClose={() => setConfirmState(s => ({ ...s, open: false }))}
        onConfirm={confirmState.onConfirm}
        title="Are you sure?"
        message={confirmState.message}
        confirmLabel="Yes, proceed"
        danger
      />
      <div className="flex items-center gap-3">
        <label className="text-sm text-ink-secondary">Domain</label>
        <select
          value={selectedDomain}
          onChange={(e) => setSelectedDomain(e.target.value)}
          className="rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
        >
          {domains.map((d) => (
            <option key={d.id} value={d.id}>{d.domain}</option>
          ))}
        </select>
      </div>

      {loading ? (
        <p className="text-ink-secondary text-sm">Loading mailboxes…</p>
      ) : mailboxes.length === 0 ? (
        <EmptyState title="No mailboxes">
          <p className="text-sm text-ink-secondary">No mailboxes configured for this domain.</p>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line">
          {mailboxes.map((mb) => (
            <li key={mb.id} className="flex items-center justify-between gap-4 px-4 py-3">
              <div>
                <p className="font-mono text-sm text-ink">{mb.local_part}</p>
                <p className="text-xs text-ink-muted">Quota: {mb.quota_mb} MB</p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <StateBadge state={mb.state} />
                <button
                  type="button"
                  onClick={() => void deleteMailbox(mb.id)}
                  className="text-xs text-ink-secondary hover:text-danger"
                >
                  Delete
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── Aliases tab ────────────────────────────────────────────────────────────────

function AliasesTab() {
  const projectId = useFirstProjectId();
  const [domains, setDomains] = useState<MailDomain[]>([]);
  const [selectedDomain, setSelectedDomain] = useState('');
  const [aliases, setAliases] = useState<MailAlias[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [confirmState, setConfirmState] = useState<{ open: boolean; message: string; onConfirm: () => void }>({ open: false, message: '', onConfirm: () => {} });

  useEffect(() => {
    if (!projectId) return;
    mailApi
      .listDomains(projectId)
      .then((r) => {
        const ds = r.domains ?? [];
        setDomains(ds);
        if (ds.length > 0) setSelectedDomain(ds[0].id);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))));
  }, [projectId]);

  useEffect(() => {
    if (!projectId || !selectedDomain) return;
    setLoading(true);
    mailApi
      .listAliases(projectId, selectedDomain)
      .then((r) => setAliases(r.aliases ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, [projectId, selectedDomain]);

  const deleteAlias = async (id: string) => {
    if (!projectId) return;
    setConfirmState({
      open: true,
      message: 'Delete this alias?',
      onConfirm: async () => {
        try {
          await mailApi.deleteAlias(projectId, selectedDomain, id);
          goeyToast.success('Alias deleted');
          setAliases((prev) => prev.filter((a) => a.id !== id));
        } catch (e) {
          const err = e instanceof Error ? e : new Error(String(e));
          goeyToast.error(`Failed to delete alias: ${err.message}`);
          setError(err);
        }
      },
    });
  };

  if (error) return <ErrorNote error={error} title="Failed to load aliases" onRetry={() => setError(null)} />;

  return (
    <div className="space-y-4">
      <ConfirmModal
        isOpen={confirmState.open}
        onClose={() => setConfirmState(s => ({ ...s, open: false }))}
        onConfirm={confirmState.onConfirm}
        title="Are you sure?"
        message={confirmState.message}
        confirmLabel="Yes, proceed"
        danger
      />
      <div className="flex items-center gap-3">
        <label className="text-sm text-ink-secondary">Domain</label>
        <select
          value={selectedDomain}
          onChange={(e) => setSelectedDomain(e.target.value)}
          className="rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
        >
          {domains.map((d) => (
            <option key={d.id} value={d.id}>{d.domain}</option>
          ))}
        </select>
      </div>

      {loading ? (
        <p className="text-ink-secondary text-sm">Loading aliases…</p>
      ) : aliases.length === 0 ? (
        <EmptyState title="No aliases">
          <p className="text-sm text-ink-secondary">No aliases configured for this domain.</p>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line">
          {aliases.map((a) => (
            <li key={a.id} className="flex items-center justify-between gap-4 px-4 py-3">
              <div>
                <p className="font-mono text-sm text-ink">{a.local_part} → {a.destination}</p>
              </div>
              <button
                type="button"
                onClick={() => void deleteAlias(a.id)}
                className="text-xs text-ink-secondary hover:text-danger"
              >
                Delete
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── Queue Log tab ──────────────────────────────────────────────────────────────

function QueueTab() {
  const projectId = useFirstProjectId();
  const [domains, setDomains] = useState<MailDomain[]>([]);
  const [selectedDomain, setSelectedDomain] = useState('');
  const [entries, setEntries] = useState<MailQueueEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    if (!projectId) return;
    mailApi
      .listDomains(projectId)
      .then((r) => {
        const ds = r.domains ?? [];
        setDomains(ds);
        if (ds.length > 0) setSelectedDomain(ds[0].id);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))));
  }, [projectId]);

  useEffect(() => {
    if (!projectId || !selectedDomain) return;
    setLoading(true);
    mailApi
      .listQueueLog(projectId, selectedDomain)
      .then((r) => setEntries(r.entries ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, [projectId, selectedDomain]);

  if (error) return <ErrorNote error={error} title="Failed to load queue log" onRetry={() => setError(null)} />;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <label className="text-sm text-ink-secondary">Domain</label>
        <select
          value={selectedDomain}
          onChange={(e) => setSelectedDomain(e.target.value)}
          className="rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
        >
          {domains.map((d) => (
            <option key={d.id} value={d.id}>{d.domain}</option>
          ))}
        </select>
      </div>

      {loading ? (
        <p className="text-ink-secondary text-sm">Loading queue log…</p>
      ) : entries.length === 0 ? (
        <EmptyState title="No queue entries">
          <p className="text-sm text-ink-secondary">No mail queue entries recorded yet.</p>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line font-mono text-xs">
          {entries.map((e) => (
            <li key={e.id} className="flex items-start gap-4 px-4 py-2">
              <span className="shrink-0 text-ink-muted w-32 truncate">{e.queued_at?.slice(0, 19).replace('T', ' ')}</span>
              <span className="text-ink truncate">{e.sender} → {e.recipients}</span>
              <span className={`shrink-0 ${e.status === 'delivered' ? 'text-green-600' : e.status === 'bounced' ? 'text-danger' : 'text-ink-secondary'}`}>
                {e.status}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── Page shell ─────────────────────────────────────────────────────────────────

export function MailPage() {
  const [tab, setTab] = useState<Tab>('domains');

  const tabs: { id: Tab; label: string }[] = [
    { id: 'domains', label: 'Domains' },
    { id: 'mailboxes', label: 'Mailboxes' },
    { id: 'aliases', label: 'Aliases' },
    { id: 'queue', label: 'Queue Log' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold tracking-wide text-ink">Mail Platform</h1>
        <p className="mt-1 text-sm text-ink-secondary">
          Manage mail domains, mailboxes, aliases, and delivery queue.
        </p>
      </div>

      <div className="flex gap-1 border-b border-line">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-sm ${
              tab === t.id
                ? 'border-b-2 border-accent font-medium text-ink'
                : 'text-ink-secondary hover:text-ink'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div>
        {tab === 'domains' && <DomainsTab />}
        {tab === 'mailboxes' && <MailboxesTab />}
        {tab === 'aliases' && <AliasesTab />}
        {tab === 'queue' && <QueueTab />}
      </div>
    </div>
  );
}
