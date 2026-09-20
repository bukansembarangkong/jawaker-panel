import { useState, type FormEvent } from 'react';

import { ApiError, api, primeCsrf, type AuthSession } from '../api/client';
import { ErrorNote, Field, inputClass, primaryButtonClass } from '../components/ui';

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
    <main className="mx-auto max-w-md px-6 py-12">
      <h1 className="text-lg font-semibold tracking-wide text-ink">JAWAKER</h1>
      <p className="mt-1 text-sm text-ink-secondary">
        {isBootstrap
          ? 'This installation has no owner yet. Create the platform owner to begin.'
          : 'Sign in to the control panel.'}
      </p>

      <form onSubmit={submit} className="mt-6 space-y-4" noValidate>
        <Field label="Email address">
          <input
            type="email"
            name="email"
            autoComplete="username"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className={inputClass}
          />
        </Field>

        {isBootstrap && (
          <Field label="Display name">
            <input
              type="text"
              name="display_name"
              autoComplete="name"
              required
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              className={inputClass}
            />
          </Field>
        )}

        <Field
          label="Password"
          hint={
            isBootstrap
              ? `At least ${MIN_PASSWORD_LENGTH} characters. Length matters more than symbols.`
              : undefined
          }
        >
          <input
            type="password"
            name="password"
            autoComplete={isBootstrap ? 'new-password' : 'current-password'}
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className={inputClass}
          />
        </Field>
        {passwordTooShort && (
          <p className="text-xs text-warn">
            The password is shorter than {MIN_PASSWORD_LENGTH} characters.
          </p>
        )}

        {secondFactorRequired && (
          <div className="rounded-md border border-line bg-subtle p-3">
            <Field
              label={useRecoveryCode ? 'Recovery code' : 'Two-factor code'}
              hint={
                useRecoveryCode
                  ? 'One of the single-use codes you saved when you enabled two-factor authentication.'
                  : 'The current 6-digit code from your authenticator app.'
              }
            >
              <input
                type="text"
                name="second_factor"
                inputMode={useRecoveryCode ? 'text' : 'numeric'}
                autoComplete="one-time-code"
                value={secondFactor}
                onChange={(e) => setSecondFactor(e.target.value)}
                className={`${inputClass} font-mono`}
              />
            </Field>
            <button
              type="button"
              onClick={() => {
                setUseRecoveryCode((v) => !v);
                setSecondFactor('');
              }}
              className="mt-2 text-xs text-ink-secondary underline"
            >
              {useRecoveryCode ? 'Use an authenticator code instead' : 'I lost my authenticator'}
            </button>
          </div>
        )}

        {error && <ErrorNote error={error} title={isBootstrap ? 'Setup failed' : 'Sign-in failed'} />}

        <button type="submit" disabled={busy} className={primaryButtonClass}>
          {busy ? 'Working…' : isBootstrap ? 'Create platform owner' : 'Sign in'}
        </button>
      </form>
    </main>
  );
}
