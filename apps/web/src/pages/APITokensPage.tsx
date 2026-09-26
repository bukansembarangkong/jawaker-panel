import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { goeyToast } from 'goey-toast';
import { tokenApi, ApiError } from '../api/client';
import type { APIToken, CreatedAPIToken } from '../api/client';
import {
  ErrorNote,
  EmptyState,
  StatusBadge,
  Modal,
  ConfirmModal,
  Field,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
} from '../components/ui';

export function APITokensPage() {
  const [tokens, setTokens] = useState<APIToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | Error | null>(null);
  const [created, setCreated] = useState<CreatedAPIToken | null>(null);
  const [copied, setCopied] = useState(false);

  const [isCreateOpen, setIsCreateOpen] = useState(false);
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
      goeyToast.success('API token created');
      setCreated(res.token);
      setName('');
      setIsCreateOpen(false);
      void load();
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      goeyToast.error(`Failed: ${e.message}`);
      setError(e);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleRevoke(id: string, tokenName: string) {
    setConfirmState({
      open: true,
      message: `Revoke token "${tokenName}"? Any application or script using this token will lose access immediately. This cannot be undone.`,
      onConfirm: async () => {
        try {
          await tokenApi.revoke(id);
          goeyToast.success('Token revoked');
          void load();
        } catch (err) {
          const e = err instanceof Error ? err : new Error(String(err));
          goeyToast.error(`Failed: ${e.message}`);
          setError(e);
        }
      },
    });
  }

  async function copyToken(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      // Fallback
    }
  }

  return (
    <div className="space-y-6">
      <ConfirmModal
        isOpen={confirmState.open}
        onClose={() => setConfirmState((s) => ({ ...s, open: false }))}
        onConfirm={confirmState.onConfirm}
        title="Revoke API Token?"
        message={confirmState.message}
        confirmLabel="Yes, revoke"
        danger
      />

      {/* Create Token Modal */}
      <Modal isOpen={isCreateOpen} onClose={() => setIsCreateOpen(false)} title="Create API Token">
        <form onSubmit={handleCreate} className="space-y-4">
          <Field label="Token Name" hint="A memorable identifier (e.g. CI/CD Deployer, Backup Script)">
            <input
              type="text"
              required
              className={inputClass}
              placeholder="e.g. github-actions-deploy"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </Field>

          <Field label="Token Type" hint="Personal tokens carry your user permissions. Service tokens are intended for automation.">
            <select
              className={inputClass}
              value={kind}
              onChange={(e) => setKind(e.target.value as 'personal' | 'service')}
            >
              <option value="personal">Personal Token</option>
              <option value="service">Service Account Token</option>
            </select>
          </Field>

          <div className="flex gap-2 justify-end pt-2">
            <button
              type="button"
              onClick={() => setIsCreateOpen(false)}
              className={secondaryButtonClass}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || !name.trim()}
              className={primaryButtonClass}
            >
              {submitting ? 'Creating…' : 'Generate Token'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Token Created Alert Modal */}
      {created && (
        <Modal isOpen={true} onClose={() => setCreated(null)} title="New API Token Generated">
          <div className="space-y-4">
            <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-800 dark:text-amber-300">
              <strong>Make sure to copy your token now.</strong> You won't be able to see it again!
            </div>

            <div>
              <label className="block text-xs font-medium text-ink-secondary mb-1">
                Token ({created.name})
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={created.plaintext}
                  className={`${inputClass} font-mono text-xs select-all`}
                />
                <button
                  type="button"
                  onClick={() => void copyToken(created.plaintext)}
                  className={primaryButtonClass}
                >
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={() => setCreated(null)}
                className={secondaryButtonClass}
              >
                I have saved this token
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-line pb-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-ink">API Tokens</h2>
          <p className="text-sm text-ink-secondary">
            Personal and service tokens for programmatic API access and CLI automation.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setIsCreateOpen(true)}
          className={primaryButtonClass}
        >
          + Create Token
        </button>
      </div>

      {error && <ErrorNote error={error} title="Token operation failed" onRetry={() => void load()} />}

      {/* Token Table */}
      {loading ? (
        <p className="text-sm text-ink-secondary">Loading tokens…</p>
      ) : tokens.length === 0 ? (
        <EmptyState title="No API Tokens">
          Create an API token to integrate external CI/CD pipelines, CLI scripts, or automated workflows.
        </EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-line bg-surface">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-line bg-elevated/50 text-xs font-semibold uppercase tracking-wider text-ink-muted">
              <tr>
                <th className="px-4 py-3">Token Name</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Prefix</th>
                <th className="px-4 py-3">Last Used</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {tokens.map((t) => (
                <tr key={t.id} className="hover:bg-elevated/40 transition-colors">
                  <td className="px-4 py-3">
                    <p className="font-medium text-ink">{t.name}</p>
                    <p className="text-xs text-ink-muted">Created {new Date(t.created_at).toLocaleDateString()}</p>
                  </td>
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center rounded-md bg-elevated px-2 py-0.5 text-xs font-medium text-ink-secondary capitalize">
                      {t.kind}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-ink-secondary">
                    {t.token_prefix}••••••••
                  </td>
                  <td className="px-4 py-3 text-xs text-ink-muted">
                    {t.last_used_at ? new Date(t.last_used_at).toLocaleString() : 'Never'}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge
                      state={t.revoked_at ? 'Disabled' : 'Healthy'}
                      detail={t.revoked_at ? 'Revoked' : 'Active'}
                    />
                  </td>
                  <td className="px-4 py-3 text-right">
                    {!t.revoked_at && (
                      <button
                        type="button"
                        className="text-xs text-danger hover:underline font-medium"
                        onClick={() => void handleRevoke(t.id, t.name)}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
