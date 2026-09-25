import { useState, type FormEvent } from 'react';

import { ApiError, api, primeCsrf, type AuthSession } from '../api/client';
import { ErrorNote } from '../components/ui';

/**
 * Bootstrap and login.
 *
 * The same form serves both because they ask for the same things; only the
 * copy and the endpoint differ. Splitting them would duplicate the error
 * handling and the second-factor step for no gain.
 *
 * The second factor appears only after the server says it is needed, which is
 * why a rejected password does not reveal whether a factor exists.
 */

const MIN_PASSWORD_LENGTH = 12;

type Mode = 'bootstrap' | 'login';

export function AuthGate({
  requiresBootstrap,
  onAuthenticated,
}: {
  requiresBootstrap: boolean;
  onAuthenticated: (session: AuthSession) => void;
}) {
  const [mode, setMode] = useState<Mode>(requiresBootstrap ? 'bootstrap' : 'login');
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [secondFactor, setSecondFactor] = useState('');
  const [secondFactorRequired, setSecondFactorRequired] = useState(false);
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | Error | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === 'bootstrap') {
        await primeCsrf();
        await api.bootstrap({ email, display_name: displayName, password });
        // Bootstrap deliberately does not create a session: there is exactly
        // one way to obtain one. Move to the login form with the email kept.
        setMode('login');
        setPassword('');
        setDisplayName('');
        return;
      }

      // A fresh token is primed per attempt: the server rotates it on
      // authentication and may have refused the cached one.
      await primeCsrf();
      await api.login({
        email,
        password,
        ...(secondFactor
          ? useRecoveryCode
            ? { recovery_code: secondFactor }
            : { totp_code: secondFactor }
          : {}),
      });
      // The session is read back rather than assembled from the login response,
      // so what the shell renders is what the server actually authorized.
      const session = await api.getSession();
      onAuthenticated(session);
    } catch (err) {
      const apiErr = err instanceof ApiError ? err : err instanceof Error ? err : new Error(String(err));
      if (apiErr instanceof ApiError && apiErr.code === 'totp_required') {
        // The password was accepted; only the second factor is outstanding.
        setSecondFactorRequired(true);
        setError(null);
        return;
      }
      setError(apiErr);
    } finally {
      setBusy(false);
    }
  }

  const isBootstrap = mode === 'bootstrap';
  const passwordTooShort = password.length > 0 && password.length < MIN_PASSWORD_LENGTH;

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-slate-50">
      <div className="w-full max-w-sm bg-white border border-slate-200/90 rounded-2xl p-7 shadow-xl shadow-slate-200/50">
        <div className="flex flex-col items-center mb-6">
          <img src="/header.png" alt="JAWAKER" className="h-9 w-auto object-contain mb-3" />
          <p className="text-xs text-slate-500 text-center font-medium">
            {isBootstrap
              ? 'First-Time Setup: Create the platform owner to begin.'
              : 'Sign in to access your server control plane.'}
          </p>
        </div>

        <form onSubmit={submit} className="space-y-4 text-xs" noValidate>
          {isBootstrap && (
            <div>
              <label className="block font-semibold text-slate-700 mb-1">Display Name</label>
              <input
                type="text"
                name="display_name"
                autoComplete="name"
                required
                placeholder="Administrator"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className="w-full bg-white border border-slate-300 rounded-lg p-2.5 text-slate-900 outline-none focus:border-indigo-600 focus:ring-2 focus:ring-indigo-100 transition"
              />
            </div>
          )}

          <div>
            <label className="block font-semibold text-slate-700 mb-1">Email address</label>
            <input
              type="email"
              name="email"
              autoComplete="username"
              required
              placeholder="admin@jawaker.local"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-white border border-slate-300 rounded-lg p-2.5 text-slate-900 outline-none focus:border-indigo-600 focus:ring-2 focus:ring-indigo-100 transition"
            />
          </div>

          <div>
            <label className="block font-semibold text-slate-700 mb-1">Password</label>
            <input
              type="password"
              name="password"
              autoComplete={isBootstrap ? 'new-password' : 'current-password'}
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-white border border-slate-300 rounded-lg p-2.5 text-slate-900 outline-none focus:border-indigo-600 focus:ring-2 focus:ring-indigo-100 transition font-mono"
            />
            {isBootstrap && (
              <p className="text-[10px] text-slate-400 mt-1">
                At least {MIN_PASSWORD_LENGTH} characters.
              </p>
            )}
          </div>
          {passwordTooShort && (
            <p className="text-xs text-amber-600">
              The password is shorter than {MIN_PASSWORD_LENGTH} characters.
            </p>
          )}

          {secondFactorRequired && (
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 space-y-2">
              <label className="block font-semibold text-slate-700">
                {useRecoveryCode ? 'Recovery code' : 'Two-Factor Authentication Code'}
              </label>
              <input
                type="text"
                name="second_factor"
                inputMode={useRecoveryCode ? 'text' : 'numeric'}
                autoComplete="one-time-code"
                placeholder={useRecoveryCode ? 'Recovery code' : '6-digit code'}
                value={secondFactor}
                onChange={(e) => setSecondFactor(e.target.value)}
                className="w-full bg-white border border-slate-300 rounded-lg p-2 text-slate-900 font-mono text-center tracking-widest text-sm outline-none focus:border-indigo-600"
              />
              <button
                type="button"
                onClick={() => {
                  setUseRecoveryCode((v) => !v);
                  setSecondFactor('');
                }}
                className="text-[10px] text-indigo-600 hover:underline"
              >
                {useRecoveryCode ? 'Use an authenticator code instead' : 'I lost my authenticator'}
              </button>
            </div>
          )}

          {error && <ErrorNote error={error} title={isBootstrap ? 'Setup failed' : 'Sign-in failed'} />}

          <button
            type="submit"
            disabled={busy}
            className="w-full bg-indigo-600 hover:bg-indigo-700 disabled:opacity-60 text-white font-semibold py-2.5 rounded-lg transition text-xs flex items-center justify-center gap-2 shadow-md shadow-indigo-600/20"
          >
            <span>{busy ? 'Working…' : isBootstrap ? 'Create Platform Owner' : 'Sign In to Panel'}</span>
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3" />
            </svg>
          </button>
        </form>
      </div>
    </div>
  );
}
