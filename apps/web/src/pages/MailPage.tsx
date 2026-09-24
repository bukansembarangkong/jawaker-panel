import { useEffect, useState } from 'react';
import { type OperationalState, EmptyState, ErrorNote, StatusBadge } from '../components/ui';
import { type MailAlias, type MailDomain, type MailMailbox, type MailQueueEntry, mailApi } from '../api/client';

type Tab = 'domains' | 'mailboxes' | 'aliases' | 'queue';

const PROJECT_ID = 'default'; // ponytail: per-project selector; add when project switcher exists

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
  const [domains, setDomains] = useState<MailDomain[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [adding, setAdding] = useState(false);
  const [newDomain, setNewDomain] = useState('');
  const [newServer, setNewServer] = useState('');
  const [saving, setSaving] = useState(false);

  const load = () => {
    setLoading(true);
    mailApi
      .listDomains(PROJECT_ID)
      .then((r) => setDomains(r.domains ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const create = async () => {
    if (!newDomain.trim() || !newServer.trim()) return;
    setSaving(true);
    try {
      await mailApi.createDomain(PROJECT_ID, newServer.trim(), newDomain.trim());
      setAdding(false);
      setNewDomain('');
      setNewServer('');
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setSaving(false);
    }
  };

  const deleteDomain = async (id: string) => {
    if (!window.confirm('Delete this mail domain? All mailboxes and aliases will be removed.')) return;
    try {
      await mailApi.deleteDomain(PROJECT_ID, id);
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  if (loading) return <p className="text-ink-secondary text-sm">Loading domains…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load mail domains" onRetry={load} />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-ink">Mail Domains ({domains.length})</h2>
        <button
          type="button"
          onClick={() => setAdding(true)}
          className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent/90"
        >
          Add Domain
        </button>
      </div>

      {adding && (
        <div className="rounded-md border border-line bg-surface p-4 space-y-3">
          <h3 className="text-sm font-medium text-ink">Add Mail Domain</h3>
          <div className="grid gap-2 sm:grid-cols-2">
            <div>
              <label className="text-xs text-ink-secondary">Domain</label>
              <input
                type="text"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                placeholder="mail.example.com"
                className="mt-1 w-full rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
              />
            </div>
            <div>
              <label className="text-xs text-ink-secondary">Server ID</label>
              <input
                type="text"
                value={newServer}
                onChange={(e) => setNewServer(e.target.value)}
                placeholder="server UUID"
                className="mt-1 w-full rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
              />
            </div>
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => void create()}
              disabled={saving}
              className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent/90 disabled:opacity-50"
            >
              {saving ? 'Saving…' : 'Save'}
            </button>
            <button
              type="button"
              onClick={() => { setAdding(false); setNewDomain(''); setNewServer(''); }}
              className="rounded-md border border-line px-3 py-1.5 text-xs text-ink-secondary hover:text-ink"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {domains.length === 0 ? (
        <EmptyState title="No mail domains">
          <p className="text-sm text-ink-secondary">Add a domain to start managing mailboxes and aliases.</p>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line">
          {domains.map((d) => (
            <li key={d.id} className="flex items-center justify-between gap-4 px-4 py-3">
              <div className="min-w-0">
                <p className="truncate font-mono text-sm text-ink">{d.domain}</p>
                <p className="text-xs text-ink-muted">{d.server_id}</p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <StateBadge state={d.state} />
                <button
                  type="button"
                  onClick={() => void deleteDomain(d.id)}
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

// ── Mailboxes tab ──────────────────────────────────────────────────────────────

function MailboxesTab() {
  const [domains, setDomains] = useState<MailDomain[]>([]);
  const [selectedDomain, setSelectedDomain] = useState('');
  const [mailboxes, setMailboxes] = useState<MailMailbox[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    mailApi
      .listDomains(PROJECT_ID)
      .then((r) => {
        const ds = r.domains ?? [];
        setDomains(ds);
        if (ds.length > 0) setSelectedDomain(ds[0].id);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))));
  }, []);

  useEffect(() => {
    if (!selectedDomain) return;
    setLoading(true);
    mailApi
      .listMailboxes(PROJECT_ID, selectedDomain)
      .then((r) => setMailboxes(r.mailboxes ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, [selectedDomain]);

  const deleteMailbox = async (id: string) => {
    if (!window.confirm('Delete this mailbox?')) return;
    try {
      await mailApi.deleteMailbox(PROJECT_ID, selectedDomain, id);
      setMailboxes((prev) => prev.filter((m) => m.id !== id));
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  if (error) return <ErrorNote error={error} title="Failed to load mailboxes" onRetry={() => setError(null)} />;

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
  const [domains, setDomains] = useState<MailDomain[]>([]);
  const [selectedDomain, setSelectedDomain] = useState('');
  const [aliases, setAliases] = useState<MailAlias[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    mailApi
      .listDomains(PROJECT_ID)
      .then((r) => {
        const ds = r.domains ?? [];
        setDomains(ds);
        if (ds.length > 0) setSelectedDomain(ds[0].id);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))));
  }, []);

  useEffect(() => {
    if (!selectedDomain) return;
    setLoading(true);
    mailApi
      .listAliases(PROJECT_ID, selectedDomain)
      .then((r) => setAliases(r.aliases ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, [selectedDomain]);

  const deleteAlias = async (id: string) => {
    if (!window.confirm('Delete this alias?')) return;
    try {
      await mailApi.deleteAlias(PROJECT_ID, selectedDomain, id);
      setAliases((prev) => prev.filter((a) => a.id !== id));
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  if (error) return <ErrorNote error={error} title="Failed to load aliases" onRetry={() => setError(null)} />;

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
  const [domains, setDomains] = useState<MailDomain[]>([]);
  const [selectedDomain, setSelectedDomain] = useState('');
  const [entries, setEntries] = useState<MailQueueEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    mailApi
      .listDomains(PROJECT_ID)
      .then((r) => {
        const ds = r.domains ?? [];
        setDomains(ds);
        if (ds.length > 0) setSelectedDomain(ds[0].id);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))));
  }, []);

  useEffect(() => {
    if (!selectedDomain) return;
    setLoading(true);
    mailApi
      .listQueueLog(PROJECT_ID, selectedDomain)
      .then((r) => setEntries(r.entries ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, [selectedDomain]);

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
