import { useEffect, useState } from 'react';

import { ErrorNote, StatusBadge, secondaryButtonClass } from './components/ui';
import { AuthGate } from './pages/AuthGate';
import { DashboardPage } from './pages/DashboardPage';
import { SecurityPage } from './pages/SecurityPage';
import { ServersPage } from './pages/ServersPage';
import { useSession } from './session/useSession';
import { useTheme } from './theme/useTheme';

/**
 * Application shell.
 *
 * Two routes, backed by the hash so a reload stays where the user was without a
 * router dependency. A router would be the right answer the moment there are
 * nested layouts and parameters; with two flat pages it would be more
 * configuration than navigation.
 *
 * Navigation is capability-aware (DESIGN_SYSTEM.md s3) in the only sense that
 * is honest today: every entry listed here is a page this build serves. No
 * disabled placeholder menus.
 *
 * Hiding a control is cosmetic. Every endpoint re-checks authorization on the
 * server, so this file is not and must never become a security boundary
 * (PRD rule: no authorization rule may exist only in frontend code).
 */

type Route = 'dashboard' | 'servers' | 'security';

function routeFromHash(): Route {
  if (window.location.hash === '#/security') return 'security';
  if (window.location.hash === '#/servers') return 'servers';
  return 'dashboard';
}

export default function App() {
  const { theme, cycle } = useTheme();
  const { state, version, controllerError, refresh, signedIn, signOut } = useSession();
  const [route, setRoute] = useState<Route>(routeFromHash);

  useEffect(() => {
    const onHashChange = () => setRoute(routeFromHash());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  if (controllerError) {
    return (
      <main className="mx-auto max-w-2xl px-6 py-12">
        <h1 className="text-lg font-semibold tracking-wide text-ink">JAWAKER</h1>
        <div className="mt-4">
          <ErrorNote
            error={controllerError}
            title="Cannot reach the controller"
            onRetry={() => void refresh()}
          />
        </div>
      </main>
    );
  }

  if (state.kind === 'loading') {
    return (
      <main className="mx-auto max-w-2xl px-6 py-12">
        <h1 className="text-lg font-semibold tracking-wide text-ink">JAWAKER</h1>
        <p role="status" className="mt-4 text-sm text-ink-secondary">
          Checking controller connection…
        </p>
      </main>
    );
  }

  if (state.kind === 'anonymous') {
    return (
      <div className="min-h-full bg-canvas">
        <AuthGate requiresBootstrap={state.requiresBootstrap} onAuthenticated={signedIn} />
        <footer className="px-6 pb-8 text-center text-xs text-ink-muted">
          UI build {__JAWAKER_VERSION__}
        </footer>
      </div>
    );
  }

  const session = state.session;

  return (
    <div className="min-h-full bg-canvas text-ink">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-line bg-surface px-6 py-4">
        <div className="flex items-baseline gap-3">
          <h1 className="text-lg font-semibold tracking-wide">JAWAKER</h1>
          <span className="font-mono text-xs text-ink-muted">control panel</span>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge state="Healthy" detail={version?.version} />
          <button
            type="button"
            onClick={cycle}
            className={secondaryButtonClass}
            aria-label={`Theme: ${theme}. Activate to switch.`}
          >
            Theme: {theme}
          </button>
          <button
            type="button"
            onClick={() => void signOut()}
            className={secondaryButtonClass}
          >
            Sign out
          </button>
        </div>
      </header>

      <div className="mx-auto flex max-w-6xl flex-col gap-8 px-6 py-8 lg:flex-row">
        <nav aria-label="Primary" className="lg:w-48 lg:shrink-0">
          <ul className="flex gap-2 lg:flex-col">
            <li>
              <a
                href="#/"
                aria-current={route === 'dashboard' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'dashboard'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Overview
              </a>
            </li>
            <li>
              <a
                href="#/servers"
                aria-current={route === 'servers' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'servers'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Servers
              </a>
            </li>
            <li>
              <a
                href="#/security"
                aria-current={route === 'security' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'security'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Security
              </a>
            </li>
          </ul>
        </nav>

        <main className="min-w-0 flex-1">
          {route === 'security' ? (
            <SecurityPage />
          ) : route === 'servers' ? (
            <ServersPage />
          ) : (
            <DashboardPage session={session} version={version} />
          )}
        </main>
      </div>

      <footer className="px-6 pb-8 text-center text-xs text-ink-muted">
        UI build {__JAWAKER_VERSION__}
      </footer>
    </div>
  );
}
