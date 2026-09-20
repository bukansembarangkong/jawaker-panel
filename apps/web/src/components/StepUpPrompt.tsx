import { useState } from 'react';

import { ApiError, api, primeCsrf } from '../api/client';
import { ErrorNote, Field, inputClass, primaryButtonClass, secondaryButtonClass } from './ui';

/**
 * The step-up re-authentication prompt (SECURITY.md §3).
 *
 * It appears when the server answers a privileged request with 403
 * `step_up_required`, which means the caller HOLDS the permission but must
 * prove they are still the person at the keyboard before it is exercised.
 *
 * This component deliberately does NOT render a "denied" message. Conflating
 * the two would send an operator hunting for a role change they do not need —
 * the distinguishing code exists precisely so the UI can offer a password box
 * instead of a dead end.
 *
 * The password is passed straight to the API and dropped on return; it is never
 * stored in state beyond the controlled input, never in localStorage.
 */

export function StepUpPrompt({
  onElevated,
  onCancel,
}: {
  /** Called once elevation succeeds, so the caller can retry the action. */
  onElevated: () => void;
  onCancel: () => void;
}) {
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [error, setError] = useState<ApiError | Error | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await primeCsrf();
      await api.elevate(password, totpCode || undefined);
      setPassword('');
      setTotpCode('');
      onElevated();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section
      aria-labelledby="stepup-heading"
      className="rounded-lg border border-warn/50 bg-surface p-5"
    >
      <h2 id="stepup-heading" className="text-base font-semibold text-ink">
        Re-authentication required
      </h2>
      <p className="mt-1 text-sm text-ink-secondary">
        This action is privileged. Confirm your password to continue; you will not be asked again
        for a short while.
      </p>

      {error && <div className="mt-3"><ErrorNote error={error} title="Could not elevate" /></div>}

      <form
        className="mt-4 space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Field label="Current password">
          <input
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className={inputClass}
            required
          />
        </Field>
        <Field label="Two-factor code" hint="Only if you have an authenticator enrolled.">
          <input
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={totpCode}
            onChange={(e) => setTotpCode(e.target.value)}
            className={`${inputClass} font-mono`}
          />
        </Field>
        <div className="flex flex-wrap gap-3">
          <button type="submit" disabled={busy || !password} className={primaryButtonClass}>
            {busy ? 'Confirming…' : 'Confirm and continue'}
          </button>
          <button type="button" onClick={onCancel} disabled={busy} className={secondaryButtonClass}>
            Cancel
          </button>
        </div>
      </form>
    </section>
  );
}
