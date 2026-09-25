import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ErrorNote, secondaryButtonClass } from '../components/ui';
import { api, type ApiError, type ResourceBudget } from '../api/client';
import { useTheme, type Theme } from '../theme/useTheme';

type Tab = 'general' | 'security' | 'sessions' | 'audit';

export function SettingsPage() {
  const { t, i18n } = useTranslation();
  const [tab, setTab] = useState<Tab>('general');
  const [_error] = useState<ApiError | Error | null>(null);
  const { theme, setTheme } = useTheme();
  const [profile, setProfile] = useState<ResourceBudget | null>(null);

  useEffect(() => {
    api.getResourceProfile().then((r) => setProfile(r.budget)).catch(() => null);
  }, []);

  const tabCls = (t: Tab) =>
    `px-4 py-2 text-sm font-medium border-b-2 ${
      tab === t
        ? 'border-accent text-ink'
        : 'border-transparent text-ink-secondary hover:text-ink'
    }`;

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-ink">Platform Settings</h1>
        <p className="text-sm text-ink-secondary mt-1">Global platform configuration and policies.</p>
      </div>

      <div className="flex border-b border-border">
        <button className={tabCls('general')} onClick={() => setTab('general')}>General</button>
        <button className={tabCls('security')} onClick={() => setTab('security')}>Security Policy</button>
        <button className={tabCls('sessions')} onClick={() => setTab('sessions')}>Session & Auth</button>
        <button className={tabCls('audit')} onClick={() => setTab('audit')}>Audit Log</button>
      </div>

      {_error && <ErrorNote error={_error} title="Settings error" />}

      {tab === 'general' && (
        <section className="space-y-6 max-w-xl">
          <div className="space-y-3">
            <h2 className="text-base font-medium text-ink">Instance</h2>
            <div>
              <label className="block text-xs text-ink-secondary mb-1">Instance Name</label>
              <input
                type="text"
                defaultValue="JAWAKER Panel"
                className="w-full rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent"
              />
            </div>
            <div>
              <label className="block text-xs text-ink-secondary mb-1">Contact Email</label>
              <input
                type="email"
                placeholder="admin@example.com"
                className="w-full rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent"
              />
            </div>
            <button className="rounded-md bg-accent px-4 py-1.5 text-sm font-medium text-white hover:bg-accent/90">
              Save Changes
            </button>
          </div>
          <div className="space-y-3">
            <h2 className="text-base font-medium text-ink">Branding</h2>
            <div>
              <label className="block text-xs text-ink-secondary mb-1">Logo URL (optional)</label>
              <input
                type="url"
                placeholder="https://…"
                className="w-full rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent"
              />
            </div>
          </div>
          <div className="space-y-3">
            <h2 className="text-base font-medium text-ink">{t('settings.language_label', 'Interface Language (PRD §43)')}</h2>
            <p className="text-xs text-ink-secondary">{t('settings.language_help', 'Switch between English and Bahasa Indonesia. Changes apply immediately.')}</p>
            <div className="flex gap-2">
              {[
                { code: 'en', label: 'English' },
                { code: 'id', label: 'Bahasa Indonesia' },
              ].map(({ code, label }) => (
                <button
                  key={code}
                  onClick={() => void i18n.changeLanguage(code)}
                  className={`px-4 py-2 rounded-md text-sm font-medium border transition-colors ${
                    i18n.language.startsWith(code)
                      ? 'bg-accent text-white border-accent'
                      : 'border-border text-ink-secondary hover:text-ink hover:border-ink-secondary'
                  }`}
                  aria-pressed={i18n.language.startsWith(code)}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
          <div className="space-y-3">
            <h2 className="text-base font-medium text-ink">Appearance</h2>
            <p className="text-xs text-ink-secondary">Choose the color theme for the JAWAKER Panel interface.</p>
            <div className="flex gap-2">
              {(['system', 'light', 'dark'] as Theme[]).map((opt) => (
                <button
                  key={opt}
                  onClick={() => setTheme(opt)}
                  className={`px-4 py-2 rounded-md text-sm font-medium border transition-colors ${
                    theme === opt
                      ? 'bg-accent text-white border-accent'
                      : 'border-border text-ink-secondary hover:text-ink hover:border-ink-secondary'
                  }`}
                  aria-pressed={theme === opt}
                >
                  {opt.charAt(0).toUpperCase() + opt.slice(1)}
                </button>
              ))}
            </div>
          </div>
          {profile && (
            <div className="space-y-3 pt-2">
              <h2 className="text-base font-medium text-ink">Adaptive Resource Profile (PRD §31)</h2>
              <div className="rounded-lg border border-border bg-surface p-4 text-xs space-y-2">
                <div className="flex justify-between items-center pb-2 border-b border-border">
                  <span className="text-ink-secondary">Capacity Profile:</span>
                  <span className="font-semibold uppercase tracking-wider text-accent">{profile.profile}</span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-ink-secondary">
                  <div>CPU Cores: <span className="font-mono text-ink">{profile.cpus}</span></div>
                  <div>RAM Detected: <span className="font-mono text-ink">{profile.total_ram_mb} MB</span></div>
                  <div>Worker Concurrency: <span className="font-mono text-ink">{profile.worker_concurrency}</span></div>
                  <div>Job Concurrency: <span className="font-mono text-ink">{profile.job_concurrency}</span></div>
                  <div>Metrics Interval: <span className="font-mono text-ink">{profile.metrics_interval_seconds}s</span></div>
                  <div>Log Retention: <span className="font-mono text-ink">{profile.log_retention_days} days</span></div>
                </div>
              </div>
            </div>
          )}
        </section>
      )}

      {tab === 'security' && (
        <section className="space-y-4 max-w-xl">
          <h2 className="text-base font-medium text-ink">Security Policies</h2>
          <div className="rounded-lg border border-border bg-surface divide-y divide-border">
            {[
              { label: 'Require TOTP for all admin accounts', default: true },
              { label: 'Block API access from unlisted CIDR ranges', default: false },
              { label: 'Auto-suspend inactive users after 90 days', default: false },
              { label: 'Require re-auth (step-up) for destructive actions', default: true },
              { label: 'Enable HSTS on all managed sites', default: true },
            ].map((policy) => (
              <label key={policy.label} className="flex items-center justify-between px-4 py-3 cursor-pointer">
                <span className="text-sm text-ink">{policy.label}</span>
                <input type="checkbox" defaultChecked={policy.default} className="ml-4" />
              </label>
            ))}
          </div>
          <button className="rounded-md bg-accent px-4 py-1.5 text-sm font-medium text-white hover:bg-accent/90">
            Save Security Policy
          </button>
        </section>
      )}

      {tab === 'sessions' && (
        <section className="space-y-4 max-w-xl">
          <h2 className="text-base font-medium text-ink">Session Configuration</h2>
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-ink-secondary mb-1">Session TTL (hours)</label>
              <input
                type="number"
                defaultValue={24}
                min={1}
                max={720}
                className="w-full rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent"
              />
            </div>
            <div>
              <label className="block text-xs text-ink-secondary mb-1">Elevation TTL (minutes)</label>
              <input
                type="number"
                defaultValue={15}
                min={5}
                max={120}
                className="w-full rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent"
              />
            </div>
            <div>
              <label className="block text-xs text-ink-secondary mb-1">Max concurrent sessions per user</label>
              <input
                type="number"
                defaultValue={5}
                min={1}
                max={50}
                className="w-full rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent"
              />
            </div>
            <button className="rounded-md bg-accent px-4 py-1.5 text-sm font-medium text-white hover:bg-accent/90">
              Save Session Config
            </button>
          </div>
        </section>
      )}

      {tab === 'audit' && (
        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-medium text-ink">Audit Log</h2>
            <button className={secondaryButtonClass}>Export CSV</button>
          </div>
          <p className="text-sm text-ink-secondary">
            Audit events are stored durably with actor, resource, request ID, and IP.
            View recent events in the Observability → Logs tab.
          </p>
          <div className="rounded-lg border border-border bg-surface p-4 text-xs text-ink-secondary">
            Audit log viewer lives in the Observability page. Every state-changing API action produces an audit event.
          </div>
        </section>
      )}
    </div>
  );
}
