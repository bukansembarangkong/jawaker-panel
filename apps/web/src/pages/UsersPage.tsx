import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { userApi, ApiError } from '../api/client';
import type { PlatformUser } from '../api/client';
import { ErrorNote, EmptyState, secondaryButtonClass } from '../components/ui';

export function UsersPage() {
  const [users, setUsers] = useState<PlatformUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | Error | null>(null);

  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [accountType, setAccountType] = useState('customer');
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<ApiError | Error | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const res = await userApi.list();
      setUsers(res.users ?? []);
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
    if (!email.trim() || !displayName.trim() || !password.trim()) return;
    setSubmitting(true);
    setFormError(null);
    try {
      await userApi.create({ email: email.trim(), display_name: displayName.trim(), password, account_type: accountType });
      setEmail('');
      setDisplayName('');
      setPassword('');
      void load();
    } catch (err) {
      setFormError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleSetState(user: PlatformUser, state: 'active' | 'suspended') {
    try {
      await userApi.setState(user.id, state);
      void load();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  }

  const [impersonationBanner, setImpersonationBanner] = useState<{ email: string; sessionId: string; expiresAt: string } | null>(null);

  async function handleImpersonate(user: PlatformUser) {
    const reason = window.prompt(`Impersonation reason / ticket ID required:`);
    if (!reason?.trim()) return;
    try {
      const res = await userApi.impersonate(user.id, reason.trim());
      setImpersonationBanner({
        email: res.user.email,
        sessionId: res.session_id,
        expiresAt: res.expires_at,
      });
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  }

  return (
    <div className="p-6 space-y-8">
      <div>
        <h1 className="text-2xl font-semibold text-ink">Users</h1>
        <p className="text-sm text-ink-secondary mt-1">Manage platform users and their roles.</p>
      </div>

      {error && (
        <ErrorNote error={error} title="Failed to load users" onRetry={() => void load()} />
      )}

      {/* Impersonation banner (PRD §5.4: clearly bannered) */}
      {impersonationBanner && (
        <div className="rounded-md border border-purple-400 bg-purple-50 dark:bg-purple-950/40 px-4 py-3 flex items-center gap-3">
          <span className="rounded bg-purple-600 px-1.5 py-0.5 text-xs font-bold text-white uppercase">Impersonation</span>
          <p className="text-sm text-purple-800 dark:text-purple-200 flex-1">
            Session created for <strong>{impersonationBanner.email}</strong> - read-only, expires {new Date(impersonationBanner.expiresAt).toLocaleString()}.
            Session ID: <code className="text-xs">{impersonationBanner.sessionId.slice(0, 8)}…</code>
          </p>
          <button
            onClick={() => setImpersonationBanner(null)}
            className="text-xs text-purple-600 hover:underline"
          >
            Dismiss
          </button>
        </div>
      )}

      <section>
        <h2 className="text-base font-medium text-ink mb-3">Invite user</h2>
        <form onSubmit={(e) => void handleCreate(e)} className="grid grid-cols-1 gap-3 sm:grid-cols-2 max-w-xl">
          <input
            type="email"
            placeholder="Email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="col-span-1 rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-ink placeholder:text-ink-muted focus:outline-none focus:ring-2 focus:ring-accent"
          />
          <input
            type="text"
            placeholder="Display name"
            required
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            className="col-span-1 rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-ink placeholder:text-ink-muted focus:outline-none focus:ring-2 focus:ring-accent"
          />
          <input
            type="password"
            placeholder="Temporary password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="col-span-1 rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-ink placeholder:text-ink-muted focus:outline-none focus:ring-2 focus:ring-accent"
          />
          <select
            value={accountType}
            onChange={(e) => setAccountType(e.target.value)}
            className="col-span-1 rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent"
          >
            <option value="customer">Customer</option>
            <option value="staff">Staff</option>
          </select>
          <div className="col-span-2 flex items-center gap-3">
            <button
              type="submit"
              disabled={submitting}
              className="rounded-md bg-accent px-4 py-1.5 text-sm font-medium text-white hover:bg-accent/90 disabled:opacity-50"
            >
              {submitting ? 'Creating…' : 'Create user'}
            </button>
          </div>
          {formError && (
            <div className="col-span-2">
              <ErrorNote error={formError} title="Failed to create user" />
            </div>
          )}
        </form>
      </section>

      <section>
        <h2 className="text-base font-medium text-ink mb-3">Platform users</h2>
        {loading ? (
          <p className="text-sm text-ink-secondary">Loading…</p>
        ) : users.length === 0 ? (
          <EmptyState title="No users yet">No platform users have been created.</EmptyState>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="bg-elevated text-ink-secondary">
                <tr>
                  <th className="px-4 py-2 text-left font-medium">Email</th>
                  <th className="px-4 py-2 text-left font-medium">Name</th>
                  <th className="px-4 py-2 text-left font-medium">Type</th>
                  <th className="px-4 py-2 text-left font-medium">State</th>
                  <th className="px-4 py-2 text-left font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {users.map((u) => (
                  <tr key={u.id} className="bg-surface hover:bg-elevated/50">
                    <td className="px-4 py-2 text-ink">
                      {u.email}
                      {u.is_owner && (
                        <span className="ml-2 rounded bg-accent/10 px-1.5 py-0.5 text-xs text-accent font-medium">owner</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-ink">{u.display_name}</td>
                    <td className="px-4 py-2 text-ink-secondary">{u.account_type}</td>
                    <td className="px-4 py-2">
                      <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${
                        u.state === 'active'
                          ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                          : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                      }`}>
                        {u.state}
                      </span>
                    </td>
                    <td className="px-4 py-2 flex items-center gap-2">
                      {!u.is_owner && (
                        <>
                          <button
                            onClick={() => void handleSetState(u, u.state === 'active' ? 'suspended' : 'active')}
                            className={secondaryButtonClass}
                          >
                            {u.state === 'active' ? 'Suspend' : 'Activate'}
                          </button>
                          <button
                            onClick={() => void handleImpersonate(u)}
                            className="rounded-md border border-purple-300 dark:border-purple-800 bg-purple-50 dark:bg-purple-950/40 px-2 py-1 text-xs font-medium text-purple-700 dark:text-purple-300 hover:bg-purple-100"
                            title="Impersonate as read-only session"
                          >
                            Impersonate
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
