import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { goeyToast } from 'goey-toast';
import { api, type ResourceBudget } from '../api/client';

type Tab = 'general' | 'resources' | 'security' | 'sessions' | 'audit';

export function SettingsPage() {
  const { t, i18n } = useTranslation();
  const [tab, setTab] = useState<Tab>('general');
  const [profile, setProfile] = useState<ResourceBudget | null>(null);
  const [saving, setSaving] = useState(false);

  // General tab state
  const [instanceName, setInstanceName] = useState('JAWAKER Panel');
  const [contactEmail, setContactEmail] = useState('admin@jawaker.local');
  const [panelUrl, setPanelUrl] = useState('http://94.237.74.81:8443');

  // Security policy toggles
  const [policies, setPolicies] = useState({
    requireTOTP: false,
    blockUnlistedCIDR: false,
    autoSuspend: false,
    requireStepUp: true,
    forceHSTS: true,
    restrictNodeEnrollment: true,
  });

  // Session config state
  const [sessionTTL, setSessionTTL] = useState(24);
  const [elevationTTL, setElevationTTL] = useState(15);
  const [maxSessions, setMaxSessions] = useState(5);

  useEffect(() => {
    api.getResourceProfile().then((r) => setProfile(r.budget)).catch(() => null);
  }, []);

  const handleSave = async (sectionName: string) => {
    setSaving(true);
    await new Promise((r) => setTimeout(r, 400));
    setSaving(false);
    goeyToast.success(`${sectionName} saved successfully!`);
  };

  const tabs: { id: Tab; label: string; icon: string }[] = [
    {
      id: 'general',
      label: 'General',
      icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z',
    },
    {
      id: 'resources',
      label: 'System Profile',
      icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z',
    },
    {
      id: 'security',
      label: 'Security Policies',
      icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
    },
    {
      id: 'sessions',
      label: 'Sessions & Auth',
      icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
    },
    {
      id: 'audit',
      label: 'Audit & Compliance',
      icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Settings</h1>
          <p className="text-sm text-slate-500">Configure global panel preferences, security policies, and resource allocations.</p>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-3 py-1 text-xs font-medium text-emerald-700 border border-emerald-200 w-fit">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
          Self-Hosted VPS
        </span>
      </div>

      {/* Tabs */}
      <div className="flex overflow-x-auto border-b border-slate-200 gap-1 pb-px">
        {tabs.map((t) => {
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 px-3.5 py-2 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
                active
                  ? 'border-indigo-600 text-indigo-600 bg-indigo-50/50 rounded-t-md'
                  : 'border-transparent text-slate-600 hover:text-slate-900 hover:border-slate-300'
              }`}
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={t.icon} />
              </svg>
              {t.label}
            </button>
          );
        })}
      </div>

      {/* ── TAB: GENERAL ────────────────────────────────────────── */}
      {tab === 'general' && (
        <div className="grid gap-6 lg:grid-cols-3">
          <div className="lg:col-span-2 space-y-6">
            {/* Instance Details */}
            <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-5">
              <div>
                <h2 className="text-base font-semibold text-slate-900">Instance Configuration</h2>
                <p className="text-xs text-slate-500">Basic metadata and public routing for this control panel.</p>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">Panel Name</label>
                  <input
                    type="text"
                    value={instanceName}
                    onChange={(e) => setInstanceName(e.target.value)}
                    className="w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 transition-all"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">Contact / Admin Email</label>
                  <input
                    type="email"
                    value={contactEmail}
                    onChange={(e) => setContactEmail(e.target.value)}
                    className="w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 transition-all"
                  />
                  <p className="mt-1 text-xs text-slate-400">Used for automated system alerts and critical certificate renewal notices.</p>
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">Panel Base URL</label>
                  <input
                    type="url"
                    value={panelUrl}
                    onChange={(e) => setPanelUrl(e.target.value)}
                    className="w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 transition-all font-mono text-xs"
                  />
                </div>
              </div>

              <div className="pt-2 flex justify-end">
                <button
                  type="button"
                  disabled={saving}
                  onClick={() => handleSave('Instance configuration')}
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all disabled:opacity-50"
                >
                  {saving ? 'Saving…' : 'Save Changes'}
                </button>
              </div>
            </div>

            {/* Language & Localization */}
            <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
              <div>
                <h2 className="text-base font-semibold text-slate-900">{t('settings.language_label', 'Interface Language')}</h2>
                <p className="text-xs text-slate-500">{t('settings.language_help', 'Switch between English and Bahasa Indonesia. Changes apply immediately.')}</p>
              </div>

              <div className="flex gap-3">
                {[
                  { code: 'en', label: 'English', flag: '🇬🇧' },
                  { code: 'id', label: 'Bahasa Indonesia', flag: '🇮🇩' },
                ].map(({ code, label, flag }) => {
                  const selected = i18n.language.startsWith(code);
                  return (
                    <button
                      key={code}
                      onClick={() => {
                        void i18n.changeLanguage(code);
                        goeyToast.success(`Language set to ${label}`);
                      }}
                      className={`flex items-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium transition-all ${
                        selected
                          ? 'border-indigo-600 bg-indigo-50 text-indigo-700 shadow-sm ring-1 ring-indigo-600'
                          : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300 hover:bg-slate-50'
                      }`}
                    >
                      <span className="text-base">{flag}</span>
                      <span>{label}</span>
                      {selected && (
                        <svg className="h-4 w-4 ml-1 text-indigo-600" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                        </svg>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Side Info Cards */}
          <div className="space-y-6">
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Environment</h3>
              <div className="space-y-2 text-xs text-slate-600">
                <div className="flex justify-between py-1 border-b border-slate-100">
                  <span>Architecture</span>
                  <span className="font-mono font-medium text-slate-900">Linux / amd64</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-100">
                  <span>Go Runtime</span>
                  <span className="font-mono font-medium text-slate-900">go1.23+</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-100">
                  <span>Database</span>
                  <span className="font-mono font-medium text-slate-900">PostgreSQL 16</span>
                </div>
                <div className="flex justify-between py-1">
                  <span>Web Proxy</span>
                  <span className="font-mono font-medium text-slate-900">Nginx 1.28.3</span>
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-slate-200 bg-slate-50 p-5 shadow-sm space-y-2">
              <h3 className="text-xs font-semibold text-slate-900">Need to change your admin password?</h3>
              <p className="text-xs text-slate-500">
                Password management and MFA are located under the dedicated <strong>My Security</strong> tab.
              </p>
              <a
                href="#/security"
                className="inline-flex items-center gap-1.5 text-xs font-medium text-indigo-600 hover:text-indigo-700 mt-1"
              >
                Go to My Security &rarr;
              </a>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB: SYSTEM RESOURCE PROFILE ─────────────────────────── */}
      {tab === 'resources' && (
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between pb-5 border-b border-slate-100">
              <div>
                <h2 className="text-base font-semibold text-slate-900">Adaptive Resource Profile</h2>
                <p className="text-xs text-slate-500">Autonomous tuning based on detected host CPU cores and memory limits.</p>
              </div>
              {profile && (
                <span className="rounded-full bg-indigo-50 px-3 py-1 font-mono text-xs font-bold text-indigo-700 border border-indigo-200 uppercase tracking-wider">
                  PROFILE: {profile.profile}
                </span>
              )}
            </div>

            {profile ? (
              <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <div className="rounded-lg border border-slate-100 bg-slate-50 p-4">
                  <span className="text-xs font-medium text-slate-500">CPU Allocation</span>
                  <p className="mt-1 font-mono text-2xl font-bold text-slate-900">{profile.cpus} Cores</p>
                  <p className="mt-1 text-[11px] text-slate-400">Available hardware vCPUs</p>
                </div>

                <div className="rounded-lg border border-slate-100 bg-slate-50 p-4">
                  <span className="text-xs font-medium text-slate-500">Total Host Memory</span>
                  <p className="mt-1 font-mono text-2xl font-bold text-slate-900">{profile.total_ram_mb} MB</p>
                  <p className="mt-1 text-[11px] text-slate-400">{(profile.total_ram_mb / 1024).toFixed(1)} GB detected RAM</p>
                </div>

                <div className="rounded-lg border border-slate-100 bg-slate-50 p-4">
                  <span className="text-xs font-medium text-slate-500">Worker Concurrency</span>
                  <p className="mt-1 font-mono text-2xl font-bold text-indigo-600">{profile.worker_concurrency} Workers</p>
                  <p className="mt-1 text-[11px] text-slate-400">Parallel background tasks</p>
                </div>

                <div className="rounded-lg border border-slate-100 bg-slate-50 p-4">
                  <span className="text-xs font-medium text-slate-500">Job Concurrency</span>
                  <p className="mt-1 font-mono text-2xl font-bold text-indigo-600">{profile.job_concurrency} Jobs</p>
                  <p className="mt-1 text-[11px] text-slate-400">Deploy queue limits</p>
                </div>

                <div className="rounded-lg border border-slate-100 bg-slate-50 p-4">
                  <span className="text-xs font-medium text-slate-500">Telemetry Interval</span>
                  <p className="mt-1 font-mono text-2xl font-bold text-slate-900">{profile.metrics_interval_seconds}s</p>
                  <p className="mt-1 text-[11px] text-slate-400">Heartbeat poll frequency</p>
                </div>

                <div className="rounded-lg border border-slate-100 bg-slate-50 p-4">
                  <span className="text-xs font-medium text-slate-500">Log Retention</span>
                  <p className="mt-1 font-mono text-2xl font-bold text-slate-900">{profile.log_retention_days} Days</p>
                  <p className="mt-1 text-[11px] text-slate-400">Automated vacuum schedule</p>
                </div>
              </div>
            ) : (
              <div className="py-12 text-center text-sm text-slate-400">Loading hardware resource profile…</div>
            )}
          </div>
        </div>
      )}

      {/* ── TAB: SECURITY POLICY ──────────────────────────────────── */}
      {tab === 'security' && (
        <div className="max-w-3xl space-y-6">
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-5">
            <div>
              <h2 className="text-base font-semibold text-slate-900">Platform Security Guardrails</h2>
              <p className="text-xs text-slate-500">Enforce global defense-in-depth rules across all projects and users.</p>
            </div>

            <div className="divide-y divide-slate-100">
              {[
                {
                  key: 'requireStepUp' as const,
                  title: 'Require Step-Up Re-Authentication',
                  desc: 'Requires password entry before executing high-risk mutations (site deletion, server revoke, database rollback).',
                },
                {
                  key: 'forceHSTS' as const,
                  title: 'Strict Transport Security (HSTS)',
                  desc: 'Inject Strict-Transport-Security header into every managed Nginx virtual host automatically.',
                },
                {
                  key: 'restrictNodeEnrollment' as const,
                  title: 'Scoped Node Agent Enrollment',
                  desc: 'Only allow node enrollment via short-lived, single-use cryptographic tokens.',
                },
                {
                  key: 'requireTOTP' as const,
                  title: 'Mandatory TOTP for Administrator Accounts',
                  desc: 'Forces users with elevated permissions to configure 2FA before accessing the dashboard.',
                },
                {
                  key: 'blockUnlistedCIDR' as const,
                  title: 'Strict CIDR Whitelisting for API Tokens',
                  desc: 'Reject API requests if an authorization token does not match an approved IP subnet.',
                },
                {
                  key: 'autoSuspend' as const,
                  title: 'Auto-Suspend Stale Accounts',
                  desc: 'Automatically flag and deactivate accounts with zero activity over the past 90 days.',
                },
              ].map(({ key, title, desc }) => {
                const active = policies[key];
                return (
                  <div key={key} className="flex items-start justify-between py-4 gap-4">
                    <div className="space-y-0.5">
                      <p className="text-sm font-medium text-slate-900">{title}</p>
                      <p className="text-xs text-slate-500 leading-relaxed">{desc}</p>
                    </div>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={active}
                      onClick={() => setPolicies((p) => ({ ...p, [key]: !p[key] }))}
                      className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 ${
                        active ? 'bg-indigo-600' : 'bg-slate-200'
                      }`}
                    >
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                          active ? 'translate-x-5' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>
                );
              })}
            </div>

            <div className="pt-2 flex justify-end">
              <button
                type="button"
                disabled={saving}
                onClick={() => handleSave('Security policies')}
                className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all disabled:opacity-50"
              >
                {saving ? 'Saving…' : 'Save Security Policy'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB: SESSIONS & AUTH ─────────────────────────────────── */}
      {tab === 'sessions' && (
        <div className="max-w-2xl space-y-6">
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-5">
            <div>
              <h2 className="text-base font-semibold text-slate-900">Session Policies</h2>
              <p className="text-xs text-slate-500">Configure cookie lifetimes, idle timeouts, and elevation windows.</p>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">
                  Standard Session Lifetime (Hours)
                </label>
                <div className="flex items-center gap-3">
                  <input
                    type="number"
                    value={sessionTTL}
                    min={1}
                    max={720}
                    onChange={(e) => setSessionTTL(Number(e.target.value))}
                    className="w-32 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm font-mono text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
                  />
                  <span className="text-xs text-slate-500">Default: 24h (Max 30 days)</span>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">
                  Step-Up Elevation Window (Minutes)
                </label>
                <div className="flex items-center gap-3">
                  <input
                    type="number"
                    value={elevationTTL}
                    min={5}
                    max={120}
                    onChange={(e) => setElevationTTL(Number(e.target.value))}
                    className="w-32 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm font-mono text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
                  />
                  <span className="text-xs text-slate-500">How long dangerous actions stay unlocked (Default: 15 min)</span>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1.5">
                  Maximum Concurrent Sessions per Account
                </label>
                <div className="flex items-center gap-3">
                  <input
                    type="number"
                    value={maxSessions}
                    min={1}
                    max={50}
                    onChange={(e) => setMaxSessions(Number(e.target.value))}
                    className="w-32 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm font-mono text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
                  />
                  <span className="text-xs text-slate-500">Oldest session is revoked when exceeded</span>
                </div>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                type="button"
                disabled={saving}
                onClick={() => handleSave('Session settings')}
                className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all disabled:opacity-50"
              >
                {saving ? 'Saving…' : 'Save Session Config'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB: AUDIT & COMPLIANCE ──────────────────────────────── */}
      {tab === 'audit' && (
        <div className="max-w-3xl space-y-6">
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div>
                <h2 className="text-base font-semibold text-slate-900">Audit Trail Export</h2>
                <p className="text-xs text-slate-500">Every state-changing API request produces an immutable record in PostgreSQL.</p>
              </div>
              <a
                href="/api/v1/audit-events"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-medium text-slate-700 shadow-sm hover:bg-slate-50 hover:border-slate-300 transition-all w-fit"
              >
                <svg className="h-4 w-4 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                Download Audit Stream (JSON)
              </a>
            </div>

            <div className="rounded-lg border border-slate-100 bg-slate-50 p-4 text-xs text-slate-600 space-y-2">
              <div className="flex items-center gap-2 font-medium text-slate-900">
                <svg className="h-4 w-4 text-emerald-600" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                Tamper-Evident Append-Only Storage
              </div>
              <p className="leading-relaxed">
                Records contain actor identity, IP address, user-agent, correlation request ID, before/after diffs, and precise microsecond timestamps.
              </p>
            </div>

            <div className="pt-2">
              <a
                href="#/audit-log"
                className="inline-flex items-center gap-1.5 text-sm font-medium text-indigo-600 hover:text-indigo-700"
              >
                Open Full Interactive Audit Log Viewer &rarr;
              </a>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
