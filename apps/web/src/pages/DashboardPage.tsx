import { useCallback, useEffect, useState } from 'react';

import { ApiError, api, type AuthSession, type MFAStatus, type VersionInfo } from '../api/client';
import {
  EmptyState,
  ErrorNote,
  MetricCard,
  StatusBadge,
  type OperationalState,
} from '../components/ui';

/**
 * Action-oriented dashboard.
 *
 * DESIGN_SYSTEM.md s4 sets the priority order: critical incidents, unhealthy
 * nodes, failed backups, failed deployments, storage pressure, expiring
 * certificates, security alerts, pending actions. Most of those signals belong
 * to modules that do not exist yet, and inventing a tile for them would be
 * fake status — so this page renders the ones the controller can actually
 * answer, and states plainly which are unavailable and why.
 *
 * The top block is the ACTION list (s4: "do not make users parse many charts
 * to learn that production is down"): only conditions that need a decision, in
 * severity order, above any metric.
 */

interface Action {
  id: string;
  state: OperationalState;
  title: string;
  detail: string;
  href?: string;
}

function deriveActions(session: AuthSession, mfa: MFAStatus | null): Action[] {
  const actions: Action[] = [];

  // A platform owner without a second factor is the highest-impact gap in the
  // current build: the account that can do anything is protected by one factor.
  if (session.user.is_owner && mfa && !mfa.totp_enrolled) {
    actions.push({
      id: 'owner-mfa',
      state: 'Critical',
      title: 'The platform owner has no second factor',
      detail:
        'Enable two-factor authentication for the owner account. It holds every permission in the panel.',
      href: '#/security',
    });
  }

  if (mfa?.totp_enrollment_pending) {
    actions.push({
      id: 'mfa-pending',
      state: 'Warning',
      title: 'A two-factor enrollment is waiting to be confirmed',
      detail:
        'The new authenticator is not active until a code confirms it. Your previous factor stays in force until then.',
      href: '#/security',
    });
  }

  // Codes are the way back in after a lost device; running out is a silent
  // lockout risk, which is exactly the kind of thing this page exists to say.
  if (mfa?.totp_enrolled && mfa.recovery_codes_remaining === 0) {
    actions.push({
      id: 'no-codes',
      state: 'Critical',
      title: 'No recovery codes remain',
      detail:
        'Nothing can bypass the second factor. Losing the authenticator would lock the account out entirely.',
      href: '#/security',
    });
  } else if (mfa?.totp_enrolled && mfa.recovery_codes_remaining <= 2) {
    actions.push({
      id: 'few-codes',
      state: 'Warning',
      title: `Only ${mfa.recovery_codes_remaining} recovery codes remain`,
      detail: 'Regenerate a fresh set before the current one runs out.',
      href: '#/security',
    });
  }

  if (mfa?.totp_enrolled && mfa.recovery_codes_remaining > 2) {
    actions.push({
      id: 'codes-ok',
      state: 'Healthy',
      title: `${mfa.recovery_codes_remaining} recovery codes available`,
      detail: 'The account can recover from a lost authenticator.',
    });
  }

  return actions;
}

export function DashboardPage({
  session,
  version,
}: {
  session: AuthSession;
  version: VersionInfo | null;
}) {
  const [mfa, setMfa] = useState<MFAStatus | null>(null);
  const [mfaError, setMfaError] = useState<ApiError | Error | null>(null);

  const loadMfa = useCallback(async () => {
    try {
      setMfa(await api.mfaStatus());
      setMfaError(null);
    } catch (err) {
      setMfaError(err instanceof Error ? err : new Error(String(err)));
    }
  }, []);

  useEffect(() => {
    void loadMfa();
  }, [loadMfa]);

  const actions = deriveActions(session, mfa);

  return (
    <div className="space-y-6">
      <section aria-labelledby="actions-heading">
        <h2 id="actions-heading" className="text-base font-semibold text-ink">
          Needs attention
        </h2>
        {mfaError ? (
          <div className="mt-3">
            <ErrorNote
              error={mfaError}
              title="Could not read security status"
              onRetry={() => void loadMfa()}
            />
          </div>
        ) : mfa === null ? (
          <p role="status" className="mt-2 text-sm text-ink-secondary">
            Checking security status…
          </p>
        ) : actions.length === 0 ? (
          <p className="mt-2 text-sm text-ink-secondary">
            Nothing needs attention in this build.
          </p>
        ) : (
          <ul className="mt-3 space-y-2">
            {actions.map((action) => (
              <li
                key={action.id}
                className="rounded-lg border border-line bg-surface p-4 text-sm"
              >
                <StatusBadge state={action.state} />
                <p className="mt-1 font-medium text-ink">{action.title}</p>
                <p className="mt-0.5 text-ink-secondary">{action.detail}</p>
                {action.href && (
                  <a href={action.href} className="mt-2 inline-block text-xs text-info underline">
                    Open security settings
                  </a>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="session-heading">
        <h2 id="session-heading" className="text-base font-semibold text-ink">
          Session
        </h2>
        <div className="mt-3 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <MetricCard label="Signed in as" value={session.user.email} mono />
          <MetricCard
            label="Account"
            value={session.user.is_owner ? 'Platform owner' : 'User'}
            hint={session.user.display_name}
          />
          <MetricCard
            label="Elevation"
            value={session.elevated ? 'Elevated' : 'Not elevated'}
            hint="Elevation is short-lived and required for sensitive operations."
          />
          <MetricCard
            label="Global permissions"
            value={session.permissions.global.length}
            mono
            hint="Effective permissions come from the server's own evaluator."
          />
          <MetricCard
            label="Two-factor"
            value={mfa ? (mfa.totp_enrolled ? 'Enabled' : 'Disabled') : '…'}
          />
          <MetricCard
            label="Recovery codes"
            value={mfa ? mfa.recovery_codes_remaining : '…'}
            mono
          />
        </div>
      </section>

      <section aria-labelledby="controller-heading">
        <h2 id="controller-heading" className="text-base font-semibold text-ink">
          Controller
        </h2>
        <div className="mt-3 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <MetricCard
            label="Status"
            value={<StatusBadge state={version ? 'Healthy' : 'Unknown'} />}
          />
          <MetricCard label="Version" value={version?.version ?? '…'} mono />
          <MetricCard label="Commit" value={version?.commit ?? '…'} mono />
        </div>
      </section>

      <section aria-labelledby="unavailable-heading">
        <h2 id="unavailable-heading" className="text-base font-semibold text-ink">
          Not yet available
        </h2>
        <div className="mt-3">
          <EmptyState title="Infrastructure and workload signals are not built yet">
            Servers, websites, backups, deployments, and certificates arrive with their phases. This
            page reports the priority order from DESIGN_SYSTEM.md only for the signals the controller
            can answer today; the rest are listed here rather than shown as empty tiles, which would
            read as &ldquo;all clear&rdquo; when nothing has been checked.
          </EmptyState>
        </div>
      </section>
    </div>
  );
}
