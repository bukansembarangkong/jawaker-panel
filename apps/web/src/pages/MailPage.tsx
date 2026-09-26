import { useEffect, useCallback, useState } from 'react';
import { goeyToast } from 'goey-toast';
import {
  type OperationalState,
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

function DnsStatusPill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${ok ? 'bg-emerald-100 text-emerald-700' : 'bg-red-100 text-red-600'}`}>
      {label} {ok ? '✓' : '✗'}
    </span>
  );
}

const thClass = 'px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50';

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
  const [expanded, setExpanded] = useState<string | null>(null);
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

  if (!projectId || loading) return <p className="text-slate-500 text-sm">Loading domains...</p>;
  if (error) return <ErrorNote error={error} title="Failed to load mail domains" onRetry={load} />;

  return (
    <div className="space-y-6">
      <ConfirmModal
        isOpen={confirmState.open}
        onClose={() => setConfirmState((s) => ({ ...s, open: false }))}
        onConfirm={confirmState.onConfirm}
        title="Are you sure?"
        message={confirmState.message}
        confirmLabel="Yes, proceed"
        danger
      />

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
              onClick={() => { setAdding(false); setNewDomain(''); }}
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
          <h2 className="text-sm font-semibold text-slate-900">Mail Domains ({domains.length})</h2>
          <p className="text-xs text-slate-500">Configure domains to receive and route incoming and outgoing emails.</p>
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
        <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
          <span className="text-4xl">✉️</span>
          <h3 className="mt-2 text-base font-semibold text-slate-900">No mail domains configured</h3>
          <p className="mt-1 text-sm text-slate-500">Add your first mail domain to configure mailboxes and aliases.</p>
        </div>
      ) : (
        <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
          <table className="w-full">
            <thead>
              <tr>
                <th className={thClass}>Domain</th>
                <th className={thClass}>Host</th>
                <th className={thClass}>Status</th>
                <th className={thClass}>DNS</th>
                <th className={thClass}>Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {domains.map((d) => (
                <>
                  <tr key={d.id}>
                    <td className="px-4 py-3 font-mono text-sm font-medium text-slate-900">{d.domain}</td>
                    <td className="px-4 py-3 text-xs text-slate-500">{getServerName(d.server_id)}</td>
                    <td className="px-4 py-3">
                      <StateBadge state={d.state} />
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        <DnsStatusPill ok={d.spf_ok} label="SPF" />
                        <DnsStatusPill ok={d.dkim_ok} label="DKIM" />
                        <DnsStatusPill ok={d.dmarc_ok} label="DMARC" />
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={() => setExpanded(expanded === d.id ? null : d.id)}
                          className={secondaryButtonClass}
                        >
                          {expanded === d.id ? 'Hide DNS' : 'DNS Setup'}
                        </button>
                        <button
                          type="button"
                          onClick={() => void deleteDomain(d.id)}
                          className="rounded-lg bg-red-600 px-3 py-2 text-sm font-medium text-white hover:bg-red-700"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                  {expanded === d.id && (
                    <tr key={`${d.id}-dns`}>
                      <td colSpan={5} className="bg-slate-50 px-6 py-4">
                        <p className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">DNS Records for {d.domain}</p>
                        <div className="rounded-lg border border-slate-200 bg-white overflow-hidden">
                          <pre className="p-4 font-mono text-xs text-slate-700 whitespace-pre-wrap leading-relaxed">{`; SPF — add as TXT record on ${d.domain}
${d.domain}.   IN TXT  "v=spf1 mx ~all"

; DKIM — add as TXT record (replace KEY with your DKIM public key)
mail._domainkey.${d.domain}.   IN TXT  "v=DKIM1; k=rsa; p=<YOUR_PUBLIC_KEY>"

; DMARC — add as TXT record on _dmarc.${d.domain}
_dmarc.${d.domain}.   IN TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@${d.domain}"

; MX — point mail to your server
${d.domain}.   IN MX  10 ${d.domain}.`}</pre>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

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
      <div className="flex items-center gap-3">
        <label className="text-sm font-medium text-slate-700">Domain</label>
        <select
          value={selectedDomain}
          onChange={(e) => setSelectedDomain(e.target.value)}
          className={inputClass}
        >
          {domains.map((d) => (
            <option key={d.id} value={d.id}>{d.domain}</option>
          ))}
        </select>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        {loading ? (
          <p className="p-6 text-sm text-slate-500">Loading mailboxes…</p>
        ) : mailboxes.length === 0 ? (
          <div className="flex flex-col items-center py-12 gap-2 text-center">
            <span className="text-3xl">📬</span>
            <p className="font-medium text-slate-700">No mailboxes</p>
            <p className="text-sm text-slate-500">No mailboxes configured for this domain.</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr>
                <th className={thClass}>Local Part</th>
                <th className={thClass}>Quota</th>
                <th className={thClass}>Status</th>
                <th className={thClass}></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {mailboxes.map((mb) => (
                <tr key={mb.id}>
                  <td className="px-4 py-3 font-mono text-sm text-slate-900">{mb.local_part}</td>
                  <td className="px-4 py-3 text-xs text-slate-500">{mb.quota_mb} MB</td>
                  <td className="px-4 py-3">
                    <StateBadge state={mb.state} />
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      onClick={() => void deleteMailbox(mb.id)}
                      className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

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
      <div className="flex items-center gap-3">
        <label className="text-sm font-medium text-slate-700">Domain</label>
        <select
          value={selectedDomain}
          onChange={(e) => setSelectedDomain(e.target.value)}
          className={inputClass}
        >
          {domains.map((d) => (
            <option key={d.id} value={d.id}>{d.domain}</option>
          ))}
        </select>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        {loading ? (
          <p className="p-6 text-sm text-slate-500">Loading aliases…</p>
        ) : aliases.length === 0 ? (
          <div className="flex flex-col items-center py-12 gap-2 text-center">
            <span className="text-3xl">↩️</span>
            <p className="font-medium text-slate-700">No aliases</p>
            <p className="text-sm text-slate-500">No aliases configured for this domain.</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr>
                <th className={thClass}>Alias</th>
                <th className={thClass}>Destination</th>
                <th className={thClass}></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {aliases.map((a) => (
                <tr key={a.id}>
                  <td className="px-4 py-3 font-mono text-sm text-slate-900">{a.local_part}</td>
                  <td className="px-4 py-3 font-mono text-sm text-slate-600">{a.destination}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      onClick={() => void deleteAlias(a.id)}
                      className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

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
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <label className="text-sm font-medium text-slate-700">Domain</label>
        <select
          value={selectedDomain}
          onChange={(e) => setSelectedDomain(e.target.value)}
          className={inputClass}
        >
          {domains.map((d) => (
            <option key={d.id} value={d.id}>{d.domain}</option>
          ))}
        </select>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        {loading ? (
          <p className="p-6 text-sm text-slate-500">Loading queue log…</p>
        ) : entries.length === 0 ? (
          <div className="flex flex-col items-center py-12 gap-2 text-center">
            <span className="text-3xl">📨</span>
            <p className="font-medium text-slate-700">No queue entries</p>
            <p className="text-sm text-slate-500">No mail queue entries recorded yet.</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr>
                <th className={thClass}>Queued at</th>
                <th className={thClass}>Sender</th>
                <th className={thClass}>Recipients</th>
                <th className={thClass}>Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {entries.map((e) => (
                <tr key={e.id}>
                  <td className="px-4 py-3 font-mono text-xs text-slate-500 shrink-0">
                    {e.queued_at?.slice(0, 19).replace('T', ' ')}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-800 truncate">{e.sender}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-700 truncate">{e.recipients}</td>
                  <td className="px-4 py-3">
                    <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                      e.status === 'delivered' ? 'bg-emerald-100 text-emerald-700' :
                      e.status === 'bounced' ? 'bg-red-100 text-red-600' :
                      'bg-slate-100 text-slate-500'
                    }`}>
                      {e.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export function MailPage() {
  const [tab, setTab] = useState<Tab>('domains');

  const tabs: { id: Tab; label: string }[] = [
    { id: 'domains', label: 'Domains' },
    { id: 'mailboxes', label: 'Mailboxes' },
    { id: 'aliases', label: 'Aliases' },
    { id: 'queue', label: 'Queue Log' },
  ];

  const tabClass = (t: Tab) =>
    `px-4 py-2 text-sm font-medium transition-colors ${
      tab === t
        ? 'border-b-2 border-indigo-600 text-indigo-600'
        : 'text-slate-500 hover:text-slate-700'
    }`;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Mail Platform</h1>
          <p className="text-sm text-slate-500">
            Manage mail domains, mailboxes, aliases, and delivery queue.
          </p>
        </div>
      </div>

      <div className="flex gap-1 border-b border-slate-200">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={tabClass(t.id)}
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
