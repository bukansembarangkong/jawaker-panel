import { useEffect, useState } from 'react';

import { ErrorNote, StatusBadge, secondaryButtonClass } from './components/ui';
import { AppsPage } from './pages/AppsPage';
import { AuthGate } from './pages/AuthGate';
import { BackupsPage } from './pages/BackupsPage';
import { ContainersPage } from './pages/ContainersPage';
import { NetworkPage } from './pages/NetworkPage';
import { SecurityCenterPage } from './pages/SecurityCenterPage';
import { UpdatesPage } from './pages/UpdatesPage';
import { MailPage } from './pages/MailPage';
import { HAPage } from './pages/HAPage';
import { ObservabilityPage } from './pages/ObservabilityPage';
import { DashboardPage } from './pages/DashboardPage';
import { DatabasesPage } from './pages/DatabasesPage';
import { DNSTLSPage } from './pages/DNSTLSPage';
import { SecurityPage } from './pages/SecurityPage';
import { ServersPage } from './pages/ServersPage';
import { SitesPage } from './pages/SitesPage';
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

type Route = 'dashboard' | 'servers' | 'security' | 'sites' | 'apps' | 'databases' | 'backups' | 'observability' | 'dnstls' | 'containers' | 'networking' | 'security-center' | 'updates' | 'mail' | 'ha';

function routeFromHash(): Route {
  if (window.location.hash === '#/security') return 'security';
  if (window.location.hash === '#/servers') return 'servers';
  if (window.location.hash === '#/sites') return 'sites';
  if (window.location.hash === '#/apps') return 'apps';
  if (window.location.hash === '#/databases') return 'databases';
  if (window.location.hash === '#/backups') return 'backups';
  if (window.location.hash === '#/observability') return 'observability';
  if (window.location.hash === '#/dnstls') return 'dnstls';
  if (window.location.hash === '#/containers') return 'containers';
  if (window.location.hash === '#/networking') return 'networking';
  if (window.location.hash === '#/security-center') return 'security-center';
  if (window.location.hash === '#/updates') return 'updates';
  if (window.location.hash === '#/mail') return 'mail';
  if (window.location.hash === '#/ha') return 'ha';
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
            <li>
              <a
                href="#/sites"
                aria-current={route === 'sites' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'sites'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Sites
              </a>
            </li>
            <li>
              <a
                href="#/apps"
                aria-current={route === 'apps' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'apps'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Apps
              </a>
            </li>
            <li>
              <a
                href="#/databases"
                aria-current={route === 'databases' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'databases'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Databases
              </a>
            </li>
            <li>
              <a
                href="#/backups"
                aria-current={route === 'backups' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'backups'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Backups
              </a>
            </li>
            <li>
              <a
                href="#/observability"
                aria-current={route === 'observability' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'observability'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Observability
              </a>
            </li>
            <li>
              <a
                href="#/dnstls"
                aria-current={route === 'dnstls' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'dnstls'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                DNS &amp; TLS
              </a>
            </li>
            <li>
              <a
                href="#/containers"
                aria-current={route === 'containers' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'containers'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Containers
              </a>
            </li>
            <li>
              <a
                href="#/networking"
                aria-current={route === 'networking' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'networking'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Networking
              </a>
            </li>
            <li>
              <a
                href="#/security-center"
                aria-current={route === 'security-center' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'security-center'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Sec Center
              </a>
            </li>
            <li>
              <a
                href="#/updates"
                aria-current={route === 'updates' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'updates'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Updates
              </a>
            </li>
            <li>
              <a
                href="#/mail"
                aria-current={route === 'mail' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'mail'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Mail
              </a>
            </li>
            <li>
              <a
                href="#/ha"
                aria-current={route === 'ha' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'ha'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                HA
              </a>
            </li>
          </ul>
        </nav>

        <main className="min-w-0 flex-1">
          {route === 'security' ? (
            <SecurityPage />
          ) : route === 'servers' ? (
            <ServersPage />
          ) : route === 'sites' ? (
            <SitesPage />
          ) : route === 'apps' ? (
            <AppsPage />
          ) : route === 'databases' ? (
            <DatabasesPage />
          ) : route === 'backups' ? (
            <BackupsPage />
          ) : route === 'observability' ? (
            <ObservabilityPage />
          ) : route === 'dnstls' ? (
            <DNSTLSPage />
          ) : route === 'containers' ? (
            <ContainersPage />
          ) : route === 'networking' ? (
            <NetworkPage />
          ) : route === 'security-center' ? (
            <SecurityCenterPage />
          ) : route === 'updates' ? (
            <UpdatesPage />
          ) : route === 'mail' ? (
            <MailPage />
          ) : route === 'ha' ? (
            <HAPage />
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
