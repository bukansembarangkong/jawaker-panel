import type { ReactNode } from 'react';

import { ApiError } from '../api/client';

/**
 * Shared UI primitives (DESIGN_SYSTEM.md s22: standardize early).
 *
 * Kept in one module because each is a dozen lines of markup and the point is
 * consistent BEHAVIOUR, not a component library: splitting these into separate
 * files would add import churn without making anything clearer.
 *
 * Two rules are enforced here for the whole app:
 *  - status is never conveyed by color alone (DESIGN_SYSTEM.md s10, s20);
 *  - every error exposes a stable code, the request id when the server sent
 *    one, and whether retrying is safe (DESIGN_SYSTEM.md s17).
 */

/** Canonical operational states (DESIGN_SYSTEM.md s10). */
export type OperationalState =
  | 'Healthy'
  | 'Warning'
  | 'Critical'
  | 'Pending'
  | 'Running'
  | 'Paused'
  | 'Disabled'
  | 'Failed'
  | 'Unknown'
  | 'Degraded'
  | 'Draining'
  | 'Updating';

const STATE_TONE: Record<OperationalState, { dot: string; text: string }> = {
  Healthy: { dot: 'bg-ok', text: 'text-ok' },
  Warning: { dot: 'bg-warn', text: 'text-warn' },
  Critical: { dot: 'bg-crit', text: 'text-crit' },
  Failed: { dot: 'bg-crit', text: 'text-crit' },
  Pending: { dot: 'bg-info', text: 'text-info' },
  Running: { dot: 'bg-info', text: 'text-info' },
  Updating: { dot: 'bg-info', text: 'text-info' },
  Draining: { dot: 'bg-warn', text: 'text-warn' },
  Degraded: { dot: 'bg-warn', text: 'text-warn' },
  Paused: { dot: 'bg-ink-muted', text: 'text-ink-muted' },
  Disabled: { dot: 'bg-ink-muted', text: 'text-ink-muted' },
  Unknown: { dot: 'bg-ink-muted', text: 'text-ink-muted' },
};

/** StatusBadge renders an operational state as dot + word. */
export function StatusBadge({ state, detail }: { state: OperationalState; detail?: string }) {
  const tone = STATE_TONE[state];
  return (
    <span className="inline-flex items-center gap-2">
      <span aria-hidden="true" className={`inline-block h-2.5 w-2.5 rounded-full ${tone.dot}`} />
      <span className={`font-medium ${tone.text}`}>{state}</span>
      {detail && <span className="text-ink-muted">{detail}</span>}
    </span>
  );
}

/** MetricCard presents one labelled value. */
export function MetricCard({
  label,
  value,
  hint,
  mono = false,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  mono?: boolean;
}) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <p className="text-xs uppercase tracking-wide text-ink-muted">{label}</p>
      <p className={`mt-1 text-lg text-ink ${mono ? 'font-mono text-base' : ''} ${mono ? 'tnum' : ''}`}>
        {value}
      </p>
      {hint && <p className="mt-1 text-xs text-ink-secondary">{hint}</p>}
    </div>
  );
}

/** EmptyState answers what this is and what to do next (DESIGN_SYSTEM.md s16). */
export function EmptyState({
  title,
  children,
  action,
}: {
  title: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-dashed border-line bg-subtle p-6 text-sm">
      <h3 className="font-medium text-ink">{title}</h3>
      <div className="mt-2 text-ink-secondary">{children}</div>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

/**
 * ErrorNote renders a failure with everything needed to act on it.
 *
 * A plain "something went wrong" is not acceptable here: without the code and
 * the request id, neither the user nor support can correlate it with anything.
 */
export function ErrorNote({
  error,
  onRetry,
  title = 'Request failed',
}: {
  error: ApiError | Error;
  onRetry?: () => void;
  title?: string;
}) {
  const apiError = error instanceof ApiError ? error : null;
  return (
    <div role="alert" className="rounded-lg border border-crit/40 bg-surface p-4 text-sm">
      <p className="font-medium text-crit">{title}</p>
      <p className="mt-1 text-ink-secondary">{error.message}</p>
      <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 font-mono text-xs text-ink-muted">
        <dt>code</dt>
        <dd>{apiError?.code ?? 'network_error'}</dd>
        {apiError?.requestId && (
          <>
            <dt>request_id</dt>
            <dd>{apiError.requestId}</dd>
          </>
        )}
        <dt>retryable</dt>
        <dd>{String(apiError?.retryable ?? true)}</dd>
      </dl>
      {onRetry && apiError?.retryable !== false && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-4 rounded-md border border-line bg-elevated px-3 py-1.5 text-ink-secondary hover:border-line-strong"
        >
          Retry
        </button>
      )}
    </div>
  );
}

/** Field is a labelled input with the shared styling. */
export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="block">
      <span className="text-sm font-medium text-ink">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-ink-muted">{hint}</span>}
    </label>
  );
}

export const inputClass =
  'mt-1 w-full rounded-md border border-line bg-elevated px-3 py-2 text-sm text-ink placeholder:text-ink-muted';

export const primaryButtonClass =
  'rounded-md bg-accent px-4 py-2 text-sm font-medium text-canvas hover:bg-accent-hover disabled:opacity-50';

export const secondaryButtonClass =
  'rounded-md border border-line bg-elevated px-3 py-1.5 text-sm text-ink-secondary hover:border-line-strong disabled:opacity-50';

export function Modal({
  title,
  isOpen,
  onClose,
  children,
}: {
  title: string;
  isOpen: boolean;
  onClose: () => void;
  children: React.ReactNode;
}) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm transition-opacity"
        onClick={onClose}
      />
      {/* Dialog box */}
      <div className="relative w-full max-w-lg rounded-xl border border-line bg-surface p-6 shadow-2xl z-10 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between border-b border-line pb-3 mb-4">
          <h3 className="text-base font-semibold text-ink">{title}</h3>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-ink-muted hover:bg-slate-100 hover:text-ink"
            aria-label="Close"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
