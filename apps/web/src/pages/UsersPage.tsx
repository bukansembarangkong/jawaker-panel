import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { goeyToast } from 'goey-toast';
import { userApi, ApiError } from '../api/client';
import type { PlatformUser } from '../api/client';
import {
  ErrorNote,
  Modal,
  ConfirmModal,
  Field,
  inputClass,
} from '../components/ui';

function UserAvatar({ name, email }: { name: string; email: string }) {
  const initials = (name || email)
    .split(' ')
    .map((w) => w[0] ?? '')
    .join('')
    .slice(0, 2)
    .toUpperCase();
  return (
    <div className="inline-flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-full bg-indigo-100 text-xs font-semibold text-indigo-700 ring-2 ring-white">
      {initials}
    </div>
  );
}

function RoleBadge({ role }: { role: string }) {
  const map: Record<string, string> = {
    customer: 'bg-slate-100 text-slate-600',
    staff: 'bg-blue-50 text-blue-700',
    admin: 'bg-purple-50 text-purple-700',
  };
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${map[role] ?? 'bg-slate-100 text-slate-600'}`}>
      {role}
    </span>
  );
}

function StateBadge({ state }: { state: string }) {
  if (state === 'active') {
    return (
      <span className="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium bg-emerald-50 text-emerald-700">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
        Active
      </span>
    );
  }
  return (
    <span className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium bg-amber-50 text-amber-700 capitalize">
      {state}
    </span>
  );
}

export function UsersPage() {
  const [users, setUsers] = useState<PlatformUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | Error | null>(null);

  // Invite modal state
  const [isInviteOpen, setIsInviteOpen] = useState(false);
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [accountType, setAccountType] = useState('customer');
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<ApiError | Error | null>(null);

  // Impersonate modal state
  const [impersonateTarget, setImpersonateTarget] = useState<PlatformUser | null>(null);
  const [impersonateReason, setImpersonateReason] = useState('');
  const [impersonating, setImpersonating] = useState(false);
  const [impersonationBanner, setImpersonationBanner] = useState<{ email: string; sessionId: string; expiresAt: string } | null>(null);

  // Suspend/activate confirm state
  const [confirmState, setConfirmState] = useState<{ open: boolean; title: string; message: string; onConfirm: () => void }>({ open: false, title: '', message: '', onConfirm: () => {} });

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
      goeyToast.success('User created successfully');
      setEmail('');
      setDisplayName('');
      setPassword('');
      setIsInviteOpen(false);
      void load();
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      goeyToast.error(`Failed: ${e.message}`);
      setFormError(e);
    } finally {
      setSubmitting(false);
    }
  }

  function handleSetState(user: PlatformUser, newState: 'active' | 'suspended') {
    setConfirmState({
      open: true,
      title: newState === 'suspended' ? 'Suspend User?' : 'Activate User?',
      message: newState === 'suspended'
        ? `Suspend "${user.display_name}"? They will lose access immediately and cannot log in until reactivated.`
        : `Reactivate "${user.display_name}"? They will regain access to the panel.`,
      onConfirm: async () => {
        try {
          await userApi.setState(user.id, newState);
          goeyToast.success(newState === 'suspended' ? 'User suspended' : 'User activated');
          void load();
        } catch (err) {
          const e = err instanceof Error ? err : new Error(String(err));
          goeyToast.error(`Failed: ${e.message}`);
          setError(e);
        }
      },
    });
  }

  async function handleImpersonate(e: FormEvent) {
    e.preventDefault();
    if (!impersonateTarget || !impersonateReason.trim()) return;
    setImpersonating(true);
    try {
      const res = await userApi.impersonate(impersonateTarget.id, impersonateReason.trim());
      goeyToast.success('Impersonation session started');
      setImpersonationBanner({
        email: res.user.email,
        sessionId: res.session_id,
        expiresAt: res.expires_at,
      });
      setImpersonateTarget(null);
      setImpersonateReason('');
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      goeyToast.error(`Failed: ${e.message}`);
      setError(e);
    } finally {
      setImpersonating(false);
    }
  }

  function generatePassword() {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    const arr = new Uint8Array(14);
    crypto.getRandomValues(arr);
    setPassword(Array.from(arr, (b) => chars[b % chars.length]).join(''));
  }

  return (
    <div className="space-y-6">
      <ConfirmModal
        isOpen={confirmState.open}
        onClose={() => setConfirmState((s) => ({ ...s, open: false }))}
        onConfirm={confirmState.onConfirm}
        title={confirmState.title}
        message={confirmState.message}
        confirmLabel="Yes, proceed"
        danger
      />

      {/* Invite User Modal */}
      <Modal isOpen={isInviteOpen} onClose={() => { setIsInviteOpen(false); setFormError(null); }} title="Invite New User">
        <form onSubmit={handleCreate} className="space-y-4">
          {formError && <ErrorNote error={formError} title="Failed to create user" />}

          <Field label="Email Address">
            <input
              type="email"
              required
              autoComplete="off"
              className={inputClass}
              placeholder="user@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </Field>

          <Field label="Display Name">
            <input
              type="text"
              required
              className={inputClass}
              placeholder="Full Name"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
            />
          </Field>

          <Field label="Temporary Password" hint="User should change this on first login.">
            <div className="flex gap-2">
              <input
                type="text"
                required
                className={`${inputClass} flex-1 font-mono`}
                placeholder="Minimum 8 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <button
                type="button"
                onClick={generatePassword}
                className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all"
                title="Generate secure password"
              >
                Generate
              </button>
            </div>
          </Field>

          <Field label="Account Type">
            <select
              className={inputClass}
              value={accountType}
              onChange={(e) => setAccountType(e.target.value)}
            >
              <option value="customer">Customer</option>
              <option value="staff">Staff</option>
            </select>
          </Field>

          <div className="flex gap-2 justify-end pt-2">
            <button
              type="button"
              onClick={() => { setIsInviteOpen(false); setFormError(null); }}
              className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || !email.trim() || !displayName.trim() || !password.trim()}
              className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all disabled:opacity-50"
            >
              {submitting ? 'Creating…' : 'Create User'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Impersonate Modal */}
      <Modal
        isOpen={impersonateTarget !== null}
        onClose={() => { setImpersonateTarget(null); setImpersonateReason(''); }}
        title={`Impersonate: ${impersonateTarget?.display_name ?? ''}`}
      >
        <form onSubmit={handleImpersonate} className="space-y-4">
          <div className="flex items-start gap-3 rounded-lg border border-purple-200 bg-purple-50 px-3 py-2.5">
            <span className="text-base">🔍</span>
            <p className="text-xs text-purple-800">This creates a read-only session as the selected user. All actions are audited.</p>
          </div>
          <Field label="Reason / Ticket ID" hint="Required for audit trail.">
            <textarea
              required
              rows={2}
              className={`${inputClass} resize-none`}
              placeholder="e.g. Support ticket #1234 - investigating login issue"
              value={impersonateReason}
              onChange={(e) => setImpersonateReason(e.target.value)}
            />
          </Field>
          <div className="flex gap-2 justify-end pt-2">
            <button
              type="button"
              onClick={() => { setImpersonateTarget(null); setImpersonateReason(''); }}
              className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={impersonating || !impersonateReason.trim()}
              className="rounded-lg bg-purple-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-purple-700 active:scale-95 transition-all disabled:opacity-50"
            >
              {impersonating ? 'Starting…' : 'Start Session'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Impersonation active banner */}
      {impersonationBanner && (
        <div className="flex items-center gap-3 rounded-xl border border-purple-200 bg-purple-50 px-4 py-3">
          <span className="rounded-md bg-purple-600 px-2 py-0.5 text-xs font-bold text-white uppercase tracking-wide">Impersonation Active</span>
          <p className="text-sm text-purple-800 flex-1">
            Read-only session as <strong>{impersonationBanner.email}</strong> — expires {new Date(impersonationBanner.expiresAt).toLocaleString()}.
          </p>
          <button onClick={() => setImpersonationBanner(null)} className="text-xs font-medium text-purple-600 hover:underline">
            Dismiss
          </button>
        </div>
      )}

      {/* Page header */}
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Users</h1>
          <p className="text-sm text-slate-500">Manage platform users, their roles, and account states.</p>
        </div>
        <button
          type="button"
          onClick={() => setIsInviteOpen(true)}
          className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all w-fit"
        >
          + Invite User
        </button>
      </div>

      {error && <ErrorNote error={error} title="Failed to load users" onRetry={() => void load()} />}

      {/* Users table */}
      <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        {loading ? (
          <div className="px-6 py-12 text-center text-sm text-slate-500">Loading users…</div>
        ) : users.length === 0 ? (
          <div className="px-6 py-16 text-center">
            <div className="text-4xl mb-3">👥</div>
            <h3 className="text-sm font-semibold text-slate-900 mb-1">No users yet</h3>
            <p className="text-sm text-slate-500">No platform users have been created yet. Invite one to get started.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">User</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Role</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Status</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-50 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3">
                        <UserAvatar name={u.display_name} email={u.email} />
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <p className="font-medium text-slate-900 truncate">{u.display_name}</p>
                            {u.is_owner && (
                              <span className="inline-flex items-center rounded-full bg-indigo-100 px-2 py-0.5 text-xs font-medium text-indigo-700">
                                Owner
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-slate-400 truncate">{u.email}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <RoleBadge role={u.account_type} />
                    </td>
                    <td className="px-4 py-3">
                      <StateBadge state={u.state} />
                    </td>
                    <td className="px-4 py-3">
                      {!u.is_owner && (
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => handleSetState(u, u.state === 'active' ? 'suspended' : 'active')}
                            className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-all"
                          >
                            {u.state === 'active' ? 'Suspend' : 'Activate'}
                          </button>
                          <button
                            type="button"
                            onClick={() => setImpersonateTarget(u)}
                            className="rounded-lg border border-purple-200 bg-purple-50 px-3 py-1.5 text-xs font-medium text-purple-700 hover:bg-purple-100 transition-all"
                            title="Impersonate as read-only session"
                          >
                            Impersonate
                          </button>
                        </div>
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
