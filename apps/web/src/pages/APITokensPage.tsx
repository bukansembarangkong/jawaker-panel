import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { tokenApi, ApiError } from '../api/client';
import type { APIToken, CreatedAPIToken } from '../api/client';
import { ErrorNote, EmptyState, secondaryButtonClass, ConfirmModal } from '../components/ui';

export function APITokensPage() {
  const [tokens, setTokens] = useState<APIToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | Error | null>(null);
  const [created, setCreated] = useState<CreatedAPIToken | null>(null);

  const [name, setName] = useState('');
  const [kind, setKind] = useState<'personal' | 'service'>('personal');
  const [submitting, setSubmitting] = useState(false);
  const [confirmState, setConfirmState] = useState<{ open: boolean; message: string; onConfirm: () => void }>({ open: false, message: '', onConfirm: () => {} });

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const res = await tokenApi.list();
      setTokens(res.tokens ?? []);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      const res = await tokenApi.create({ name: name.trim(), kind });
      setCreated(res.token);
      setName('');
      void load();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleRevoke(id: string) {
    setConfirmState({
      open: true,
      message: 'Revoke this token? This cannot be undone.',
      onConfirm: async () => {
        try {
          await tokenApi.revoke(id);
          void load();
        } catch (err) {
          setError(err instanceof Error ? err : new Error(String(err)));
        }
      },
    });
  }

  return (
    <div className="space-y-8">
      <ConfirmModal
        isOpen={confirmState.open}
        onClose={() => setConfirmState(s => ({ ...s, open: false }))}
        onConfirm={confirmState.onConfirm}
        title="Are you sure?"
        message={confirmState.message}
        confirmLabel="Yes, proceed"
        danger
      />
      <header>
        <h2 className="text-xl font-semibold">API Tokens</h2>
        <p className="mt-1 text-sm text-ink-secondary">
          Personal and service tokens for programmatic API access. The plaintext value is shown once at creation.
        </p>
      </header>

      {error && <ErrorNote error={error} title="Token operation failed" onRetry={() => void load()} />}

      {created && (
        <div className="rounded-md border border-line bg-elevated p-4">
          <p className="text-sm font-medium text-ok">Token created. Copy it now - it will not be shown again.</p>
          <code className="mt-2 block break-all rounded bg-canvas p-2 font-mono text-xs">{created.plaintext}</code>
          <button type="button" className="mt-2 text-xs text-ink-muted underline" onClick={() => setCreated(null)}>
            Dismiss
          </button>
        </div>
      )}

      <form onSubmit={handleCreate} className="flex flex-wrap items-end gap-3 rounded-md border border-line bg-surface p-4">
        <label className="flex flex-col text-sm">
          Name
          <input
            className="mt-1 rounded border border-line bg-canvas px-2 py-1"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </label>
        <label className="flex flex-col text-sm">
          Kind
          <select
            className="mt-1 rounded border border-line bg-canvas px-2 py-1"
            value={kind}
            onChange={(e) => setKind(e.target.value as 'personal' | 'service')}
          >
            <option value="personal">personal</option>
            <option value="service">service</option>
          </select>
        </label>
        <button
          type="submit"
          disabled={submitting}
          className={secondaryButtonClass}
        >
          {submitting ? 'Creating…' : 'Create token'}
        </button>
      </form>

      {loading ? (
        <p className="text-sm text-ink-secondary">Loading tokens…</p>
      ) : tokens.length === 0 ? (
        <EmptyState title="No tokens">Create a token to use the CLI or API.</EmptyState>
      ) : (
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-line text-ink-muted">
              <th className="py-2">Name</th>
              <th>Kind</th>
              <th>Prefix</th>
              <th>Last used</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {tokens.map((t) => (
              <tr key={t.id} className="border-b border-line">
                <td className="py-2 font-medium">{t.name}</td>
                <td>{t.kind}</td>
                <td className="font-mono text-xs">{t.token_prefix}…</td>
                <td>{t.last_used_at ? new Date(t.last_used_at).toLocaleString() : '-'}</td>
                <td>{t.revoked_at ? 'revoked' : 'active'}</td>
                <td className="text-right">
                  {!t.revoked_at && (
                    <button type="button" className="text-crit underline" onClick={() => void handleRevoke(t.id)}>
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
