import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { goeyToast } from 'goey-toast';
import { tokenApi, ApiError } from '../api/client';
import type { APIToken, CreatedAPIToken } from '../api/client';
import {
  ErrorNote,
  Modal,
  ConfirmModal,
  Field,
  inputClass,
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
              className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || !name.trim()}
              className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all disabled:opacity-50"
            >
              {submitting ? 'Creating…' : 'Generate Token'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Token Reveal Modal */}
      {created && (
        <Modal isOpen={true} onClose={() => setCreated(null)} title="New API Token Generated">
          <div className="space-y-4">
            <div className="flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 p-3">
              <span className="text-lg">⚠️</span>
              <p className="text-xs text-amber-800">
                <strong>Copy your token now.</strong> You won't be able to see it again after closing this dialog.
              </p>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1.5">
                Token — <span className="font-semibold text-slate-800">{created.name}</span>
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={created.plaintext}
                  className="flex-1 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-800 select-all focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
                <button
                  type="button"
                  onClick={() => void copyToken(created.plaintext)}
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
                >
                  {copied ? '✓ Copied!' : 'Copy'}
                </button>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={() => setCreated(null)}
                className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all"
              >
                I have saved this token
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Header */}
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">API Tokens</h1>
          <p className="text-sm text-slate-500">Personal and service tokens for programmatic API access and CLI automation.</p>
        </div>
        <button
          type="button"
          onClick={() => setIsCreateOpen(true)}
          className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all w-fit"
        >
          + Create Token
        </button>
      </div>

      {error && <ErrorNote error={error} title="Token operation failed" onRetry={() => void load()} />}

      {/* Token Table */}
      <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        {loading ? (
          <div className="px-6 py-12 text-center text-sm text-slate-500">Loading tokens…</div>
        ) : tokens.length === 0 ? (
          <div className="px-6 py-16 text-center">
            <div className="text-4xl mb-3">🔑</div>
            <h3 className="text-sm font-semibold text-slate-900 mb-1">No API Tokens</h3>
            <p className="text-sm text-slate-500">Create an API token to integrate CI/CD pipelines, CLI scripts, or automated workflows.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Name</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Kind</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Prefix</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Last Used</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Status</th>
                  <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {tokens.map((t) => (
                  <tr key={t.id} className="hover:bg-slate-50 transition-colors">
                    <td className="px-4 py-3">
                      <p className="font-medium text-slate-900">{t.name}</p>
                      <p className="text-xs text-slate-400">Created {new Date(t.created_at).toLocaleDateString()}</p>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${t.kind === 'service' ? 'bg-amber-50 text-amber-700' : 'bg-slate-100 text-slate-600'}`}>
                        {t.kind}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-500">
                      {t.token_prefix}<span className="tracking-widest">••••••</span>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-500">
                      {t.last_used_at ? new Date(t.last_used_at).toLocaleString() : <span className="text-slate-400">Never</span>}
                    </td>
                    <td className="px-4 py-3">
                      {t.revoked_at ? (
                        <span className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium bg-red-50 text-red-700">
                          Revoked
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium bg-emerald-50 text-emerald-700">
                          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                          Active
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {!t.revoked_at && (
                        <button
                          type="button"
                          className="rounded-lg border border-red-200 bg-white px-3 py-1.5 text-xs font-medium text-red-600 hover:bg-red-50 transition-all"
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
    </div>
  );
}
