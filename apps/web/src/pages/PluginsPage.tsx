import { useEffect, useState } from 'react';
import { type OperationalState, EmptyState, ErrorNote, StatusBadge, ConfirmModal } from '../components/ui';
import { type Plugin, pluginsApi } from '../api/client';

type Tab = 'installed' | 'quarantined';

function pluginState(state: string): OperationalState {
  const map: Record<string, OperationalState> = {
    installing: 'Running',
    installed: 'Pending',
    enabled: 'Healthy',
    disabled: 'Paused',
    quarantined: 'Failed',
    removed: 'Disabled',
  };
  return map[state] ?? 'Unknown';
}

function trustBadge(trust: string): string {
  const map: Record<string, string> = {
    official: 'text-green-600 font-semibold',
    verified: 'text-blue-600',
    community: 'text-yellow-600',
    unverified: 'text-ink-muted',
  };
  return map[trust] ?? 'text-ink-muted';
}

// ── Installed tab ─────────────────────────────────────────────────────────────

function InstalledTab() {
  const [ps, setPs] = useState<Plugin[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [confirmState, setConfirmState] = useState<{ open: boolean; message: string; onConfirm: () => void }>({ open: false, message: '', onConfirm: () => {} });

  const load = () => {
    setLoading(true);
    pluginsApi
      .listPlugins()
      .then((r) => setPs(r.plugins ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const enable = async (id: string) => {
    try {
      await pluginsApi.enablePlugin(id);
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  const disable = async (id: string) => {
    try {
      await pluginsApi.disablePlugin(id);
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  const uninstall = async (id: string) => {
    setConfirmState({
      open: true,
      message: 'Uninstall this plugin?',
      onConfirm: async () => {
        try {
          await pluginsApi.uninstallPlugin(id);
          load();
        } catch (e) {
          setError(e instanceof Error ? e : new Error(String(e)));
        }
      },
    });
  };

  const quarantine = async (id: string) => {
    const reason = window.prompt('Reason for quarantine:');
    if (!reason) return;
    try {
      await pluginsApi.quarantinePlugin(id, reason);
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  if (loading) return <p className="text-ink-secondary text-sm">Loading plugins…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load plugins" onRetry={load} />;

  return (
    <div className="space-y-4">
      <ConfirmModal
        isOpen={confirmState.open}
        onClose={() => setConfirmState(s => ({ ...s, open: false }))}
        onConfirm={confirmState.onConfirm}
        title="Are you sure?"
        message={confirmState.message}
        confirmLabel="Yes, proceed"
        danger
      />
      <h2 className="text-sm font-medium text-ink">Installed Plugins ({ps.length})</h2>

      {ps.length === 0 ? (
        <EmptyState title="No plugins installed">
          <p className="text-sm text-ink-secondary">No plugins registered yet. Use the API to register a plugin.</p>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line">
          {ps.map((plugin) => (
            <li key={plugin.id} className="px-4 py-3">
              <div className="flex items-center justify-between gap-4">
                <div className="min-w-0">
                  <p className="font-medium text-sm text-ink">{plugin.display_name || plugin.name}</p>
                  <p className="text-xs text-ink-muted">
                    v{plugin.version} ·{' '}
                    <span className={trustBadge(plugin.trust_level)}>{plugin.trust_level}</span>
                    {plugin.author && ` · ${plugin.author}`}
                  </p>
                  {plugin.description && <p className="text-xs text-ink-secondary mt-0.5">{plugin.description}</p>}
                </div>
                <div className="flex items-center gap-2 shrink-0 flex-wrap justify-end">
                  <StatusBadge state={pluginState(plugin.state)} detail={plugin.state} />
                  {plugin.state === 'installed' || plugin.state === 'disabled' ? (
                    <button
                      type="button"
                      onClick={() => void enable(plugin.id)}
                      className="text-xs text-ink-secondary hover:text-ink"
                    >
                      Enable
                    </button>
                  ) : null}
                  {plugin.state === 'enabled' ? (
                    <button
                      type="button"
                      onClick={() => void disable(plugin.id)}
                      className="text-xs text-ink-secondary hover:text-ink"
                    >
                      Disable
                    </button>
                  ) : null}
                  {plugin.state !== 'quarantined' && plugin.state !== 'removed' && (
                    <button
                      type="button"
                      onClick={() => void quarantine(plugin.id)}
                      className="text-xs text-ink-secondary hover:text-orange-600"
                    >
                      Quarantine
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => void uninstall(plugin.id)}
                    className="text-xs text-ink-secondary hover:text-danger"
                  >
                    Uninstall
                  </button>
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── Quarantined tab ───────────────────────────────────────────────────────────

function QuarantinedTab() {
  const [ps, setPs] = useState<Plugin[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const load = () => {
    setLoading(true);
    pluginsApi
      .listPlugins('quarantined')
      .then((r) => setPs(r.plugins ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  if (loading) return <p className="text-ink-secondary text-sm">Loading quarantined plugins…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load quarantined plugins" onRetry={load} />;

  return (
    <div className="space-y-4">
      <h2 className="text-sm font-medium text-ink">Quarantined Plugins ({ps.length})</h2>

      {ps.length === 0 ? (
        <EmptyState title="No quarantined plugins">
          <p className="text-sm text-ink-secondary">No plugins currently quarantined.</p>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line">
          {ps.map((plugin) => (
            <li key={plugin.id} className="flex items-center justify-between gap-4 px-4 py-3">
              <div>
                <p className="font-medium text-sm text-ink">{plugin.display_name || plugin.name}</p>
                <p className="text-xs text-ink-muted">v{plugin.version} · {plugin.trust_level}</p>
              </div>
              <StatusBadge state="Failed" detail="quarantined" />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── Page shell ────────────────────────────────────────────────────────────────

export function PluginsPage() {
  const [tab, setTab] = useState<Tab>('installed');

  const tabs: { id: Tab; label: string }[] = [
    { id: 'installed', label: 'Plugins' },
    { id: 'quarantined', label: 'Quarantined' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold tracking-wide text-ink">Plugin SDK</h1>
        <p className="mt-1 text-sm text-ink-secondary">
          Manage third-party plugins. No plugin receives implicit privilege.
          Permission escalation requires explicit review.
        </p>
      </div>

      <div className="flex gap-1 border-b border-line">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-sm ${
              tab === t.id
                ? 'border-b-2 border-accent font-medium text-ink'
                : 'text-ink-secondary hover:text-ink'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div>
        {tab === 'installed' && <InstalledTab />}
        {tab === 'quarantined' && <QuarantinedTab />}
      </div>
    </div>
  );
}
