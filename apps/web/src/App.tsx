import { useCallback, useEffect, useState } from 'react';

import { ApiError, api, type VersionInfo } from './api/client';
import { useTheme } from './theme/useTheme';

/**
 * Phase 0 shell — intentionally minimal and honest.
 *
 * It renders only what actually exists: controller connectivity, build
 * metadata, and the theme control. Navigation and feature pages arrive with
 * their phases; placeholder menus for unbuilt features are forbidden
 * (rule: no fake status).
 */

type ConnectionState =
  | { kind: 'loading' }
  | { kind: 'connected'; version: VersionInfo }
  | { kind: 'error'; message: string; code: string; requestId?: string; retryable: boolean };

export default function App() {
  const { theme, cycle } = useTheme();
  const [connection, setConnection] = useState<ConnectionState>({ kind: 'loading' });

  const refresh = useCallback(async () => {
    setConnection({ kind: 'loading' });
    try {
      const version = await api.getVersion();
      setConnection({ kind: 'connected', version });
    } catch (err) {
      if (err instanceof ApiError) {
        setConnection({
          kind: 'error',
          message: err.message,
          code: err.code,
          requestId: err.requestId,
          retryable: err.retryable,
        });
      } else {
        setConnection({
          kind: 'error',
          message: 'Cannot reach the controller API.',
          code: 'network_error',
          retryable: true,
        });
      }
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <div className="min-h-full bg-canvas text-ink">
      <header className="flex items-center justify-between border-b border-line bg-surface px-6 py-4">
        <div className="flex items-baseline gap-3">
          <h1 className="text-lg font-semibold tracking-wide">JAWAKER</h1>
          <span className="font-mono text-xs text-ink-muted">control panel</span>
        </div>
        <button
          type="button"
          onClick={cycle}
          className="rounded-md border border-line bg-elevated px-3 py-1.5 text-sm text-ink-secondary hover:border-line-strong"
          aria-label={`Theme: ${theme}. Activate to switch.`}
        >
          Theme: {theme}
        </button>
      </header>

      <main className="mx-auto max-w-3xl px-6 py-10">
        <section
          aria-labelledby="controller-status-heading"
          className="rounded-lg border border-line bg-surface p-6"
        >
          <h2 id="controller-status-heading" className="mb-4 text-base font-semibold">
            Controller status
          </h2>
          <ConnectionPanel state={connection} onRetry={refresh} />
        </section>

        <section aria-labelledby="phase-heading" className="mt-6 rounded-lg border border-line bg-surface p-6">
          <h2 id="phase-heading" className="mb-2 text-base font-semibold">
            Phase 0 — engineering foundation
          </h2>
          <p className="text-sm text-ink-secondary">
            This build contains the repository foundation: controller skeleton, migration
            framework, CI pipeline, and this UI shell. Product features start in Phase 1.
          </p>
        </section>
      </main>

      <footer className="px-6 pb-8 text-center text-xs text-ink-muted">
        UI build {__JAWAKER_VERSION__}
      </footer>
    </div>
  );
}

function ConnectionPanel({ state, onRetry }: { state: ConnectionState; onRetry: () => void }) {
  switch (state.kind) {
    case 'loading':
      return (
        <p role="status" className="text-sm text-ink-secondary">
          Checking controller connection…
        </p>
      );
    case 'connected':
      return (
        <div className="text-sm">
          <p className="flex items-center gap-2">
            {/* Status conveyed by text + color, never color alone. */}
            <span
              aria-hidden="true"
              className="inline-block h-2.5 w-2.5 rounded-full bg-ok"
            />
            <span className="font-medium text-ok">Connected</span>
          </p>
          <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 font-mono text-xs text-ink-secondary">
            <dt className="text-ink-muted">version</dt>
            <dd>{state.version.version}</dd>
            <dt className="text-ink-muted">commit</dt>
            <dd>{state.version.commit}</dd>
            <dt className="text-ink-muted">built</dt>
            <dd>{state.version.build_time}</dd>
          </dl>
        </div>
      );
    case 'error':
      return (
        <div className="text-sm" role="alert">
          <p className="flex items-center gap-2">
            <span
              aria-hidden="true"
              className="inline-block h-2.5 w-2.5 rounded-full bg-crit"
            />
            <span className="font-medium text-crit">Disconnected</span>
          </p>
          <p className="mt-2 text-ink-secondary">{state.message}</p>
          <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 font-mono text-xs text-ink-muted">
            <dt>code</dt>
            <dd>{state.code}</dd>
            {state.requestId && (
              <>
                <dt>request_id</dt>
                <dd>{state.requestId}</dd>
              </>
            )}
            <dt>retryable</dt>
            <dd>{String(state.retryable)}</dd>
          </dl>
          <button
            type="button"
            onClick={onRetry}
            className="mt-4 rounded-md border border-line bg-elevated px-3 py-1.5 text-sm text-ink-secondary hover:border-line-strong"
          >
            Retry
          </button>
        </div>
      );
  }
}
