import { useEffect, useState } from 'react';
import { GoeyToaster } from 'goey-toast';

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
import { CopilotPage } from './pages/CopilotPage';
import { PluginsPage } from './pages/PluginsPage';
import { HardeningPage } from './pages/HardeningPage';
import { APITokensPage } from './pages/APITokensPage';
import { UsersPage } from './pages/UsersPage';
import { NotificationsPage } from './pages/NotificationsPage';
import { WorkersPage } from './pages/WorkersPage';
import { FilesPage } from './pages/FilesPage';
import { AuditLogPage } from './pages/AuditLogPage';
import { SettingsPage } from './pages/SettingsPage';
import { DRWizardPage } from './pages/DRWizardPage';
import { AutomationPage } from './pages/AutomationPage';
import { CommandPalette } from './components/CommandPalette';
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

type Route = 'dashboard' | 'servers' | 'security' | 'sites' | 'apps' | 'databases' | 'backups' | 'observability' | 'dnstls' | 'containers' | 'networking' | 'security-center' | 'updates' | 'mail' | 'ha' | 'copilot' | 'plugins' | 'hardening' | 'api-tokens' | 'users' | 'notifications' | 'workers' | 'files' | 'settings' | 'dr-wizard' | 'automation' | 'audit-log';

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
  if (window.location.hash === '#/copilot') return 'copilot';
  if (window.location.hash === '#/plugins') return 'plugins';
  if (window.location.hash === '#/hardening') return 'hardening';
  if (window.location.hash === '#/api-tokens') return 'api-tokens';
  if (window.location.hash === '#/users') return 'users';
  if (window.location.hash === '#/notifications') return 'notifications';
  if (window.location.hash === '#/workers') return 'workers';
  if (window.location.hash === '#/files') return 'files';
  if (window.location.hash === '#/settings') return 'settings';
  if (window.location.hash === '#/dr-wizard') return 'dr-wizard';
  if (window.location.hash === '#/automation') return 'automation';
  if (window.location.hash === '#/audit-log') return 'audit-log';
  return 'dashboard';
}

export default function App() {
  const { theme, cycle } = useTheme();
  const { state, version, controllerError, refresh, signedIn, signOut } = useSession();
  const [route, setRoute] = useState<Route>(routeFromHash);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [servers, setServers] = useState<{ id: string; name: string }[]>([]);
  const [selectedServerId, setSelectedServerId] = useState<string>(
    () => localStorage.getItem('jawaker_selected_server') ?? '',
  );

  useEffect(() => {
    const onHashChange = () => setRoute(routeFromHash());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setPaletteOpen((prev) => !prev);
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  useEffect(() => {
    if (state.kind !== 'authenticated') return;
    import('./api/client').then(({ api }) => {
      api.listServers().then((res) => {
        setServers(res.servers);
        if (res.servers.length > 0) {
          const stored = localStorage.getItem('jawaker_selected_server');
          const matched = res.servers.find((s) => s.id === stored);
          if (matched) {
            setSelectedServerId(matched.id);
          } else {
            setSelectedServerId(res.servers[0].id);
            localStorage.setItem('jawaker_selected_server', res.servers[0].id);
          }
        }
      }).catch(() => {});
    });
  }, [state.kind]);

  if (controllerError) {
    return (
      <main className="mx-auto max-w-2xl px-6 py-12">
        <img src="/header.png" alt="JAWAKER" className="h-8 w-auto" />
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
        <img src="/header.png" alt="JAWAKER" className="h-8 w-auto" />
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
        <div className="flex items-center gap-3">
          <img src="/header.png" alt="JAWAKER" className="h-8 w-auto" />
          <span className="font-mono text-xs text-ink-muted">control panel</span>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge state="Healthy" detail={version?.version} />
          {servers.length > 0 && (
            <div className="flex items-center gap-1.5 rounded-lg border border-border bg-elevated px-2.5 py-1 text-xs">
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              <select
                value={selectedServerId}
                onChange={(e) => {
                  setSelectedServerId(e.target.value);
                  localStorage.setItem('jawaker_selected_server', e.target.value);
                }}
                className="bg-transparent font-medium text-ink outline-none"
              >
                {servers.map((s) => (
                  <option key={s.id} value={s.id}>{s.name}</option>
                ))}
              </select>
            </div>
          )}
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
            <li>
              <a
                href="#/copilot"
                aria-current={route === 'copilot' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'copilot'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                AI Copilot
              </a>
            </li>
            <li>
              <a
                href="#/plugins"
                aria-current={route === 'plugins' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'plugins'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Plugins
              </a>
            </li>
            <li>
              <a
                href="#/hardening"
                aria-current={route === 'hardening' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'hardening'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Hardening
              </a>
            </li>
            <li>
              <a
                href="#/api-tokens"
                aria-current={route === 'api-tokens' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'api-tokens'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                API Tokens
              </a>
            </li>
            <li>
              <a
                href="#/users"
                aria-current={route === 'users' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'users'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Users
              </a>
            </li>
            <li>
              <a
                href="#/notifications"
                aria-current={route === 'notifications' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'notifications'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Notifications
              </a>
            </li>
            <li>
              <a
                href="#/workers"
                aria-current={route === 'workers' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'workers'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Workers
              </a>
            </li>
            <li>
              <a
                href="#/files"
                aria-current={route === 'files' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'files'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Files
              </a>
            </li>
            <li>
              <a
                href="#/settings"
                aria-current={route === 'settings' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'settings'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Settings
              </a>
            </li>
            <li>
              <a
                href="#/dr-wizard"
                aria-current={route === 'dr-wizard' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'dr-wizard'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                DR Wizard
              </a>
            </li>
            <li>
              <a
                href="#/automation"
                aria-current={route === 'automation' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'automation'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Automation
              </a>
            </li>
            <li>
              <a
                href="#/audit-log"
                aria-current={route === 'audit-log' ? 'page' : undefined}
                className={`block rounded-md px-3 py-1.5 text-sm ${
                  route === 'audit-log'
                    ? 'bg-elevated font-medium text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                Audit Log
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
          ) : route === 'copilot' ? (
            <CopilotPage />
          ) : route === 'plugins' ? (
            <PluginsPage />
          ) : route === 'hardening' ? (
            <HardeningPage />
          ) : route === 'api-tokens' ? (
            <APITokensPage />
          ) : route === 'users' ? (
            <UsersPage />
          ) : route === 'notifications' ? (
            <NotificationsPage />
          ) : route === 'workers' ? (
            <WorkersPage />
          ) : route === 'files' ? (
            <FilesPage />
          ) : route === 'settings' ? (
            <SettingsPage />
          ) : route === 'dr-wizard' ? (
            <DRWizardPage />
          ) : route === 'automation' ? (
            <AutomationPage />
          ) : route === 'audit-log' ? (
            <AuditLogPage />
          ) : (
            <DashboardPage session={session} version={version} />
          )}
        </main>
      </div>

      <footer className="px-6 pb-8 text-center text-xs text-ink-muted">
        UI build {__JAWAKER_VERSION__}{' '}
        <button
          onClick={() => setPaletteOpen(true)}
          className="ml-2 rounded border border-border px-1.5 py-0.5 text-xs text-ink-muted hover:text-ink"
          title="Open command palette (Ctrl+K)"
        >
          Ctrl+K
        </button>
      </footer>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
      <GoeyToaster position="bottom-right" />
    </div>
  );
}
