import { useEffect, useState } from 'react';
import { GoeyToaster } from 'goey-toast';

import { ErrorNote } from './components/ui';
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
  useTheme();
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

  const pageTitles: Record<Route, string> = {
    dashboard: 'Dashboard Overview',
    servers: 'Servers',
    sites: 'Websites & Sites',
    apps: 'Deployments (Git)',
    containers: 'App Store & Containers',
    databases: 'Databases',
    files: 'File Manager',
    dnstls: 'DNS & TLS',
    backups: 'Backups & DR',
    networking: 'Networking',
    'security-center': 'Security Center',
    observability: 'Monitoring & Observability',
    security: 'Security',
    updates: 'Updates',
    mail: 'Mail',
    ha: 'High Availability',
    copilot: 'AI Copilot',
    plugins: 'Plugins',
    hardening: 'Hardening',
    'api-tokens': 'API Tokens',
    users: 'Users',
    notifications: 'Notifications',
    workers: 'Background Workers',
    automation: 'Automation',
    'audit-log': 'Audit Log',
    settings: 'Settings',
    'dr-wizard': 'DR Wizard',
  };

  type NavItem = { route: Route; label: string; icon: string };
  type NavSection = { heading: string; items: NavItem[] };

  const navSections: NavSection[] = [
    {
      heading: 'Core Hosting',
      items: [
        { route: 'dashboard', label: 'Dashboard', icon: 'M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z' },
        { route: 'sites', label: 'Sites', icon: 'M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9' },
        { route: 'apps', label: 'Apps', icon: 'M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10' },
        { route: 'containers', label: 'App Store', icon: 'M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z' },
        { route: 'databases', label: 'Databases', icon: 'M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4' },
        { route: 'files', label: 'File Manager', icon: 'M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z' },
      ],
    },
    {
      heading: 'Infrastructure',
      items: [
        { route: 'dnstls', label: 'DNS & TLS', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
        { route: 'backups', label: 'Backups & DR', icon: 'M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4' },
        { route: 'networking', label: 'Networking', icon: 'M4 6h16M4 12h16M4 18h16' },
        { route: 'security-center', label: 'Security Center', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z' },
        { route: 'observability', label: 'Monitoring', icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z' },
      ],
    },
    {
      heading: 'Platform',
      items: [
        { route: 'servers', label: 'Servers', icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2' },
        { route: 'updates', label: 'Updates', icon: 'M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15' },
        { route: 'mail', label: 'Mail', icon: 'M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z' },
        { route: 'ha', label: 'HA', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
        { route: 'copilot', label: 'AI Copilot', icon: 'M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z' },
        { route: 'plugins', label: 'Plugins', icon: 'M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z' },
        { route: 'hardening', label: 'Hardening', icon: 'M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01' },
      ],
    },
    {
      heading: 'Admin',
      items: [
        { route: 'api-tokens', label: 'API Tokens', icon: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z' },
        { route: 'users', label: 'Users', icon: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z' },
        { route: 'notifications', label: 'Notifications', icon: 'M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9' },
        { route: 'workers', label: 'Workers', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z' },
        { route: 'automation', label: 'Automation', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
        { route: 'audit-log', label: 'Audit Log', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01' },
        { route: 'settings', label: 'Settings', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065zM15 12a3 3 0 11-6 0 3 3 0 016 0z' },
        { route: 'dr-wizard', label: 'DR Wizard', icon: 'M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15' },
      ],
    },
  ];

  const avatarInitials = (session.user.email ?? '').slice(0, 2).toUpperCase();

  return (
    <div className="flex h-screen overflow-hidden bg-slate-50">
      {/* Sidebar */}
      <aside className="flex w-64 shrink-0 flex-col border-r border-slate-200 bg-white">
        {/* Sidebar header */}
        <div className="flex h-16 shrink-0 items-center justify-center border-b border-slate-100 px-4">
          <img src="/header.png" alt="JAWAKER" className="h-7 w-auto" />
        </div>

        {/* Server selector pill */}
        <div className="border-b border-slate-100 px-3 py-2">
          {servers.length > 0 ? (
            <div className="flex items-center gap-2 rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1.5">
              <span className="h-2 w-2 shrink-0 rounded-full bg-emerald-500" />
              <select
                value={selectedServerId}
                onChange={(e) => {
                  setSelectedServerId(e.target.value);
                  localStorage.setItem('jawaker_selected_server', e.target.value);
                }}
                className="min-w-0 flex-1 truncate bg-transparent text-xs font-medium text-slate-700 outline-none"
              >
                {servers.map((s) => (
                  <option key={s.id} value={s.id}>{s.name}</option>
                ))}
              </select>
            </div>
          ) : (
            <div className="flex items-center gap-2 rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1.5">
              <span className="h-2 w-2 shrink-0 rounded-full bg-slate-300" />
              <span className="truncate text-xs text-slate-400">No servers enrolled</span>
            </div>
          )}
        </div>

        {/* Nav menu */}
        <nav className="flex-1 overflow-y-auto px-2 py-3" aria-label="Primary">
          {navSections.map((section) => (
            <div key={section.heading} className="mb-4">
              <p className="mb-1 px-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                {section.heading}
              </p>
              <ul className="space-y-0.5">
                {section.items.map((item) => {
                  const active = route === item.route;
                  return (
                    <li key={item.route}>
                      <a
                        href={`#/${item.route === 'dashboard' ? '' : item.route}`}
                        aria-current={active ? 'page' : undefined}
                        className={`flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm ${
                          active
                            ? 'bg-indigo-50 font-semibold text-indigo-700'
                            : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                        }`}
                      >
                        <svg
                          className="h-4 w-4 shrink-0"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                          strokeWidth={1.5}
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        >
                          <path d={item.icon} />
                        </svg>
                        {item.label}
                      </a>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>

        {/* Sidebar footer */}
        <div className="shrink-0 border-t border-slate-100 p-3">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-indigo-100 text-xs font-semibold text-indigo-700">
              {avatarInitials}
            </div>
            <span className="min-w-0 flex-1 truncate text-xs text-slate-600">
              {session.user.email}
            </span>
            <button
              type="button"
              onClick={() => void signOut()}
              className="shrink-0 rounded px-1.5 py-1 text-xs text-slate-500 hover:bg-slate-100 hover:text-slate-900"
            >
              Sign Out
            </button>
          </div>
        </div>
      </aside>

      {/* Main area */}
      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        {/* Top bar */}
        <div className="flex h-14 shrink-0 items-center justify-between border-b border-slate-200 bg-white px-6">
          <h2 className="text-base font-semibold text-slate-800">
            {pageTitles[route]}
          </h2>
          <div className="flex items-center gap-2">

            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              className="rounded border border-slate-200 px-2.5 py-1 text-xs text-slate-500 hover:bg-slate-50 hover:text-slate-800"
              title="Open command palette (Ctrl+K)"
            >
              Ctrl+K
            </button>
          </div>
        </div>

        {/* Scrollable content */}
        <main className="flex-1 overflow-y-auto p-6">
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

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
      <GoeyToaster position="bottom-right" />
    </div>
  );
}
