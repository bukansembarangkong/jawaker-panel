import { useCallback, useEffect, useState } from 'react';
import { goeyToast } from 'goey-toast';
import { QRCodeSVG } from 'qrcode.react';

import { ApiError, api, primeCsrf, type MFAStatus } from '../api/client';
import {
  ErrorNote,
  Field,
  MetricCard,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
} from '../components/ui';

/**
 * Two-factor self-service (DESIGN_SYSTEM.md s12: separate secret fields;
 * SECURITY.md s3).
 *
 * The screen walks through the real lifecycle and nothing else. There is no
 * "coming soon" section: showing controls for a step the server cannot perform
 * would be a fake status (rule s22).
 *
 * Codes are shown exactly once, with an explicit warning that they will not be
 * retrievable later, because they are not — only their digests are stored.
 */

type Step = 'none' | 'pending' | 'enrolled';

interface PendingEnrollment {
  secret: string;
  otpauth_uri: string;
  period_seconds: number;
}

export function SecurityPage() {
  const [status, setStatus] = useState<MFAStatus | null>(null);
  const [pending, setPending] = useState<PendingEnrollment | null>(null);
  const [error, setError] = useState<ApiError | Error | null>(null);
  const [busy, setBusy] = useState(false);

  // Form state, one field per input so nothing is shared by accident.
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [reason, setReason] = useState('');
  const [issuedCodes, setIssuedCodes] = useState<string[] | null>(null);

  const load = useCallback(async () => {
    try {
      const s = await api.mfaStatus();
      setStatus(s);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const step: Step = status ? (status.totp_enrolled ? 'enrolled' : status.totp_enrollment_pending ? 'pending' : 'none') : 'none';

  async function enroll() {
    setBusy(true);
    setError(null);
    try {
      await primeCsrf();
      const result = await api.mfaEnroll(password);
      setPending({
        secret: result.secret,
        otpauth_uri: result.otpauth_uri,
        period_seconds: result.period_seconds,
      });
      setPassword('');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  }

  async function confirm() {
    setBusy(true);
    setError(null);
    try {
      await primeCsrf();
      const result = await api.mfaConfirm(code);
      setIssuedCodes(result.recovery_codes ?? null);
      if (result.recovery_codes_error) {
        setError(new Error(result.recovery_codes_error));
      }
      setPending(null);
      setCode('');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  }

  async function disable() {
    setBusy(true);
    setError(null);
    try {
      await primeCsrf();
      await api.mfaDisable(password, reason);
      setPassword('');
      setReason('');
      setIssuedCodes(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  }

  async function regenerate() {
    setBusy(true);
    setError(null);
    try {
      await primeCsrf();
      const result = await api.mfaRegenerateRecoveryCodes(password, code || undefined);
      setIssuedCodes(result.recovery_codes);
      setPassword('');
      setCode('');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  }

  if (!status && !error) {
    return (
      <p role="status" className="text-sm text-ink-secondary">
        Loading security settings…
      </p>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2">
        <MetricCard
          label="Two-factor authentication"
          value={step === 'enrolled' ? 'Enabled' : step === 'pending' ? 'Enrollment in progress' : 'Disabled'}
        />
        <MetricCard
          label="Recovery codes remaining"
          value={status?.recovery_codes_remaining ?? 0}
          mono
        />
      </div>

      {error && <ErrorNote error={error} onRetry={step === 'enrolled' || step === 'none' ? () => void load() : undefined} />}

      {issuedCodes && <RecoveryCodeList codes={issuedCodes} onDismiss={() => setIssuedCodes(null)} />}

      <div className="grid gap-6 lg:grid-cols-2 items-start">
        <div className="space-y-6">
          {step === 'none' && (
        <section className="rounded-lg border border-line bg-surface p-5">
          <h2 className="text-base font-semibold text-ink">Enable two-factor authentication</h2>
          <p className="mt-1 text-sm text-ink-secondary">
            Confirm your password to start. You will then scan a QR code or enter the key in your
            authenticator app, and confirm with a code.
          </p>
          <form
            className="mt-4 space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              void enroll();
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
            <button type="submit" disabled={busy || !password} className={primaryButtonClass}>
              {busy ? 'Working…' : 'Begin enrollment'}
            </button>
          </form>
        </section>
      )}

      {step === 'pending' && pending && (
        <section className="rounded-lg border border-line bg-surface p-5">
          <h2 className="text-base font-semibold text-ink">Confirm your authenticator</h2>
          <p className="mt-1 text-sm text-ink-secondary">
            Add this account to your authenticator app, then enter the code it shows.
          </p>
          <div className="mt-4 flex flex-col items-center gap-4 sm:flex-row sm:items-start">
            <div className="flex shrink-0 items-center justify-center rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
              <QRCodeSVG
                value={pending.otpauth_uri}
                size={168}
                level="M"
                includeMargin={false}
              />
            </div>
            <div className="min-w-0 flex-1 space-y-2 text-sm">
              <p className="text-xs font-medium text-ink-muted uppercase tracking-wider">Manual Entry</p>
              <div className="flex items-center gap-2">
                <code className="block flex-1 rounded bg-slate-100 px-2.5 py-1.5 font-mono text-xs text-ink select-all break-all border border-slate-200">
                  {pending.secret}
                </code>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(pending.secret);
                    goeyToast.success('Secret key copied to clipboard!');
                  }}
                  className="shrink-0 rounded border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-colors"
                >
                  Copy
                </button>
              </div>
              <p className="text-xs text-ink-muted">
                Scan the QR code with Google Authenticator, Authy, or any TOTP app. Code refreshes every {pending.period_seconds}s.
              </p>
            </div>
          </div>
          <form
            className="mt-4 space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              void confirm();
            }}
          >
            <Field label="Authenticator code">
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                className={`${inputClass} font-mono`}
                required
              />
            </Field>
            <button type="submit" disabled={busy || !code} className={primaryButtonClass}>
              {busy ? 'Working…' : 'Confirm and enable'}
            </button>
          </form>
        </section>
      )}

      {step === 'enrolled' && (
        <>
          <section className="rounded-lg border border-line bg-surface p-5">
            <h2 className="text-base font-semibold text-ink">Recovery codes</h2>
            <p className="mt-1 text-sm text-ink-secondary">
              Regenerate a fresh set. This replaces any previous codes and requires your password and
              a current authenticator code.
            </p>
            <form
              className="mt-4 space-y-4"
              onSubmit={(e) => {
                e.preventDefault();
                void regenerate();
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
              <Field label="Authenticator code">
                <input
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  className={`${inputClass} font-mono`}
                  required
                />
              </Field>
              <button type="submit" disabled={busy || !password || !code} className={primaryButtonClass}>
                {busy ? 'Working…' : 'Regenerate recovery codes'}
              </button>
            </form>
          </section>

          <section className="rounded-lg border border-crit/40 bg-surface p-5">
            <h2 className="text-base font-semibold text-crit">Disable two-factor authentication</h2>
            <p className="mt-1 text-sm text-ink-secondary">
              This removes your second factor, deletes all recovery codes, and signs you out of every
              device. You will need your password and a reason.
            </p>
            <form
              className="mt-4 space-y-4"
              onSubmit={(e) => {
                e.preventDefault();
                void disable();
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
              <Field label="Reason" hint="Recorded in the audit log.">
                <input
                  type="text"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  className={inputClass}
                  required
                />
              </Field>
              <button type="submit" disabled={busy || !password || !reason} className={secondaryButtonClass}>
                {busy ? 'Working…' : 'Disable two-factor authentication'}
              </button>
            </form>
          </section>
        </>
      )}
        </div>{/* end left col */}

        {/* Right column: Change Password */}
        <ChangePasswordSection />
      </div>{/* end grid */}
    </div>
  );
}

function ChangePasswordSection() {
  const [currentPw, setCurrentPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    if (newPw.length < 12) {
      goeyToast.error('New password must be at least 12 characters.');
      return;
    }
    if (newPw !== confirmPw) {
      goeyToast.error('New password and confirmation do not match.');
      return;
    }
    if (newPw === currentPw) {
      goeyToast.error('New password must be different from current password.');
      return;
    }

    setBusy(true);
    try {
      await primeCsrf();
      const res = await api.changePassword(currentPw, newPw);
      goeyToast.success(res.message || 'Password changed successfully!');
      setCurrentPw('');
      setNewPw('');
      setConfirmPw('');
    } catch (err: any) {
      goeyToast.error(err?.message || 'Failed to change password. Check your current password.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded-lg border border-border bg-surface p-5">
      <h2 className="text-base font-semibold text-ink">Change Account Password</h2>
      <p className="mt-1 text-sm text-ink-muted">
        Update the password for your current administrator session. Minimum 12 characters.
      </p>

      <form onSubmit={handleSubmit} className="mt-4 space-y-4">
        <Field label="Current Password" hint="The password you used to log in.">
          <input
            type="password"
            value={currentPw}
            onChange={(e) => setCurrentPw(e.target.value)}
            className={inputClass}
            autoComplete="current-password"
            required
          />
        </Field>
        <Field label="New Password" hint="At least 12 characters long.">
          <input
            type="password"
            value={newPw}
            onChange={(e) => setNewPw(e.target.value)}
            className={inputClass}
            autoComplete="new-password"
            required
            minLength={12}
          />
        </Field>
        <Field label="Confirm New Password" hint="Type the new password again.">
          <input
            type="password"
            value={confirmPw}
            onChange={(e) => setConfirmPw(e.target.value)}
            className={inputClass}
            autoComplete="new-password"
            required
            minLength={12}
          />
        </Field>
        <button
          type="submit"
          disabled={busy || !currentPw || !newPw || !confirmPw}
          className={primaryButtonClass}
        >
          {busy ? 'Updating…' : 'Update Password'}
        </button>
      </form>
    </section>
  );
}

/** RecoveryCodeList shows codes once, with the warning that they are not stored. */
function RecoveryCodeList({ codes, onDismiss }: { codes: string[]; onDismiss: () => void }) {
  return (
    <section className="rounded-lg border border-warn/50 bg-surface p-5">
      <h2 className="text-base font-semibold text-ink">Your recovery codes</h2>
      <p className="mt-1 text-sm text-warn">
        Save these now. They are shown once and are not stored in a recoverable form. Each code works
        a single time if you lose your authenticator.
      </p>
      <ul className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 font-mono text-sm text-ink">
        {codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>
      <button type="button" onClick={onDismiss} className={`${secondaryButtonClass} mt-4`}>
        I have saved these
      </button>
    </section>
  );
}
