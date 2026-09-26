import React, { useCallback, useEffect, useState } from 'react';

import { ApiError, api, type AuthSession, type MFAStatus, type VersionInfo } from '../api/client';
import {
  EmptyState,
  ErrorNote,
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

const ACTION_BORDER: Record<string, string> = {
  Critical: 'border-l-4 border-l-red-500',
  Warning:  'border-l-4 border-l-amber-400',
  Healthy:  'border-l-4 border-l-emerald-500',
};

const ACTION_PILL: Record<string, string> = {
  Critical: 'bg-red-50 text-red-700 border border-red-200',
  Warning:  'bg-amber-50 text-amber-700 border border-amber-200',
  Healthy:  'bg-emerald-50 text-emerald-700 border border-emerald-200',
};

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
      {/* Header */}
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Dashboard</h1>
          <p className="text-sm text-slate-500">
            Security status and session overview for this control panel session.
          </p>
        </div>
        <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium border w-fit ${version ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-100 text-slate-500 border-slate-200'}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${version ? 'bg-emerald-500' : 'bg-slate-400'}`} />
          {version ? 'Controller Online' : 'Controller Unknown'}
        </span>
      </div>

      {/* Needs attention */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
        <div>
          <h2 className="text-base font-semibold text-slate-900">Needs Attention</h2>
          <p className="text-xs text-slate-500">Security and account action items in priority order.</p>
        </div>

        {mfaError ? (
          <ErrorNote
            error={mfaError}
            title="Could not read security status"
            onRetry={() => void loadMfa()}
          />
        ) : mfa === null ? (
          <p role="status" className="text-sm text-slate-400">Checking security status…</p>
        ) : actions.length === 0 ? (
          <p className="text-sm text-slate-400">Nothing needs attention in this build.</p>
        ) : (
          <ul className="space-y-2">
            {actions.map((action) => {
              const border = ACTION_BORDER[action.state] ?? 'border-l-4 border-l-slate-300';
              const pill   = ACTION_PILL[action.state]  ?? 'bg-slate-100 text-slate-600 border border-slate-200';
              return (
                <li
                  key={action.id}
                  className={`flex items-start gap-4 rounded-lg border border-slate-100 bg-slate-50 p-4 ${border}`}
                >
                  <div className="flex-1 space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${pill}`}>
                        {action.state}
                      </span>
                    </div>
                    <p className="mt-1 text-sm font-medium text-slate-900">{action.title}</p>
                    <p className="text-xs text-slate-500 leading-relaxed">{action.detail}</p>
                    {action.href && (
                      <a href={action.href} className="mt-1.5 inline-block text-xs font-medium text-indigo-600 hover:text-indigo-700">
                        Open security settings →
                      </a>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* Session metrics */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
        <div>
          <h2 className="text-base font-semibold text-slate-900">Session</h2>
          <p className="text-xs text-slate-500">Current authentication state for this session.</p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <StatCard label="Signed in as"       value={session.user.email}                                  mono />
          <StatCard label="Account"            value={session.user.is_owner ? 'Platform owner' : 'User'}  hint={session.user.display_name} />
          <StatCard label="Elevation"          value={session.elevated ? 'Elevated' : 'Not elevated'}      hint="Elevation is short-lived and required for sensitive operations." />
          <StatCard label="Global permissions" value={String(session.permissions.global.length)}           mono hint="Effective permissions come from the server's own evaluator." />
          <StatCard label="Two-factor"         value={mfa ? (mfa.totp_enrolled ? 'Enabled' : 'Disabled') : '…'} />
          <StatCard label="Recovery codes"     value={mfa ? String(mfa.recovery_codes_remaining) : '…'}   mono />
        </div>
      </div>

      {/* Controller / version */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
        <div>
          <h2 className="text-base font-semibold text-slate-900">Controller</h2>
          <p className="text-xs text-slate-500">Panel backend build information.</p>
        </div>
        <div className="grid gap-4 sm:grid-cols-3">
          <StatCard
            label="Status"
            value={
              <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${version ? 'bg-emerald-50 text-emerald-700' : 'bg-slate-100 text-slate-500'}`}>
                <span className={`h-1.5 w-1.5 rounded-full ${version ? 'bg-emerald-500' : 'bg-slate-400'}`} />
                {version ? 'Healthy' : 'Unknown'}
              </span>
            }
          />
          <StatCard label="Version" value={version?.version ?? '…'} mono />
          <StatCard label="Commit"  value={version?.commit  ?? '…'} mono />
        </div>
      </div>

      {/* Not yet available */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-3">
        <div>
          <h2 className="text-base font-semibold text-slate-900">Not Yet Available</h2>
          <p className="text-xs text-slate-500">Signals pending module implementation.</p>
        </div>
        <EmptyState title="Infrastructure and workload signals are not built yet">
          Servers, websites, backups, deployments, and certificates arrive with their modules. This
          page reports status only for the signals the controller
          can answer today; the rest are listed here rather than shown as empty tiles, which would
          read as &ldquo;all clear&rdquo; when nothing has been checked.
        </EmptyState>
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  hint,
  mono = false,
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  mono?: boolean;
}) {
  return (
    <div className="rounded-lg border border-slate-100 bg-slate-50 p-4">
      <p className="text-xs font-medium uppercase tracking-wider text-slate-500">{label}</p>
      <p className={`mt-1 text-sm font-semibold text-slate-900 ${mono ? 'font-mono' : ''}`}>{value}</p>
      {hint && <p className="mt-1 text-[11px] text-slate-400 leading-relaxed">{hint}</p>}
    </div>
  );
}
