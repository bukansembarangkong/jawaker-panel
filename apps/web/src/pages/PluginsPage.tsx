import { useEffect, useState } from 'react';
import { goeyToast } from 'goey-toast';
import { type OperationalState, ErrorNote, StatusBadge, ConfirmModal } from '../components/ui';
import { type Plugin, pluginsApi } from '../api/client';

type Tab = 'installed' | 'quarantined';

function pluginState(state: string): OperationalState {
  const map: Record<string, OperationalState> = {
    installing: 'Running', installed: 'Pending', enabled: 'Healthy', disabled: 'Paused', quarantined: 'Failed', removed: 'Disabled',
  };
  return map[state] ?? 'Unknown';
}

function trustBadgeClass(trust: string): string {
  switch (trust) {
    case 'official': return 'bg-emerald-50 text-emerald-700 border border-emerald-200';
    case 'verified': return 'bg-blue-50 text-blue-700 border border-blue-200';
    case 'community': return 'bg-amber-50 text-amber-700 border border-amber-200';
    default: return 'bg-slate-100 text-slate-600 border border-slate-200';
  }
}

// ?? Installed tab ?????????????????????????????????????????????????????????????

function InstalledTab() {
  const [ps, setPs] = useState<Plugin[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [confirmState, setConfirmState] = useState<{ open: boolean; message: string; onConfirm: () => void }>({ open: false, message: '', onConfirm: () => {} });

  const load = () => {
    setLoading(true);
    pluginsApi.listPlugins()
      .then((r) => setPs(r.plugins ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const enable = async (id: string) => {
    try { await pluginsApi.enablePlugin(id); goeyToast.success('Plugin enabled'); load(); }
    catch (err) { const e = err instanceof Error ? err : new Error(String(err)); goeyToast.error(`Failed: ${e.message}`); setError(e); }
  };

  const disable = async (id: string) => {
    try { await pluginsApi.disablePlugin(id); goeyToast.success('Plugin disabled'); load(); }
    catch (err) { const e = err instanceof Error ? err : new Error(String(err)); goeyToast.error(`Failed: ${e.message}`); setError(e); }
  };

  const uninstall = async (id: string) => {
    setConfirmState({
      open: true, message: 'Uninstall this plugin?',
      onConfirm: async () => {
        try { await pluginsApi.uninstallPlugin(id); goeyToast.success('Plugin uninstalled'); load(); }
        catch (err) { const e = err instanceof Error ? err : new Error(String(err)); goeyToast.error(`Failed: ${e.message}`); setError(e); }
      },
    });
  };

  const quarantine = async (id: string) => {
    const reason = window.prompt('Reason for quarantine:');
    if (!reason) return;
    try { await pluginsApi.quarantinePlugin(id, reason); goeyToast.success('Plugin quarantined'); load(); }
    catch (err) { const e = err instanceof Error ? err : new Error(String(err)); goeyToast.error(`Failed: ${e.message}`); setError(e); }
  };

  if (loading) return <p className="text-slate-500 text-sm">Loading plugins?</p>;
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

      {ps.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
          <div className="text-4xl mb-3">??</div>
          <h3 className="text-base font-semibold text-slate-900">No plugins installed</h3>
          <p className="text-sm text-slate-500 mt-1">No plugins registered yet. Use the API or marketplace to register plugins.</p>
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {ps.map((plugin) => (
            <div key={plugin.id} className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between space-y-4 hover:shadow-md transition-shadow">
              <div className="space-y-2">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl p-2 bg-slate-50 rounded-lg border border-slate-100">??</span>
                    <div>
                      <h3 className="font-semibold text-slate-900">{plugin.display_name || plugin.name}</h3>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <span className="rounded-full px-2 py-0.5 text-xs font-mono font-medium bg-slate-100 text-slate-700">
                          v{plugin.version}
                        </span>
                        <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${trustBadgeClass(plugin.trust_level)}`}>
                          {plugin.trust_level}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {plugin.author && (
                  <p className="text-xs text-slate-500">By <span className="font-medium text-slate-700">{plugin.author}</span></p>
                )}
                {plugin.description && (
                  <p className="text-xs text-slate-600 line-clamp-2">{plugin.description}</p>
                )}
              </div>

              <div className="space-y-3 pt-3 border-t border-slate-100">
                <div className="flex items-center justify-between">
                  <StatusBadge state={pluginState(plugin.state)} detail={plugin.state} />
                  <div className="flex items-center gap-2">
                    {plugin.state === 'installed' || plugin.state === 'disabled' ? (
                      <button
                        type="button"
                        onClick={() => void enable(plugin.id)}
                        className="rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
                      >
                        Enable
                      </button>
                    ) : null}
                    {plugin.state === 'enabled' ? (
                      <button
                        type="button"
                        onClick={() => void disable(plugin.id)}
                        className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-all"
                      >
                        Disable
                      </button>
                    ) : null}
                  </div>
                </div>

                <div className="flex items-center justify-end gap-2 pt-1">
                  {plugin.state !== 'quarantined' && plugin.state !== 'removed' && (
                    <button
                      type="button"
                      onClick={() => void quarantine(plugin.id)}
                      className="rounded-lg border border-amber-200 bg-amber-50 px-2.5 py-1 text-xs font-medium text-amber-700 hover:bg-amber-100 transition-all"
                    >
                      Quarantine
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => void uninstall(plugin.id)}
                    className="rounded-lg border border-red-200 bg-red-50 px-2.5 py-1 text-xs font-medium text-red-600 hover:bg-red-100 transition-all"
                  >
                    Uninstall
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ?? Quarantined tab ???????????????????????????????????????????????????????????

function QuarantinedTab() {
  const [ps, setPs] = useState<Plugin[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const load = () => {
    setLoading(true);
    pluginsApi.listPlugins('quarantined')
      .then((r) => setPs(r.plugins ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  if (loading) return <p className="text-slate-500 text-sm">Loading quarantined plugins?</p>;
  if (error) return <ErrorNote error={error} title="Failed to load quarantined plugins" onRetry={load} />;

  return (
    <div className="space-y-4">
      {ps.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
          <div className="text-4xl mb-3">???</div>
          <h3 className="text-base font-semibold text-slate-900">No quarantined plugins</h3>
          <p className="text-sm text-slate-500 mt-1">All installed plugins are running without restriction.</p>
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {ps.map((plugin) => (
            <div key={plugin.id} className="rounded-xl border border-red-300 bg-red-50/30 p-6 shadow-sm flex flex-col justify-between space-y-4">
              <div className="space-y-2">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl p-2 bg-red-100 rounded-lg">??</span>
                    <div>
                      <h3 className="font-semibold text-slate-900">{plugin.display_name || plugin.name}</h3>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <span className="rounded-full px-2 py-0.5 text-xs font-mono font-medium bg-red-100 text-red-800">
                          v{plugin.version}
                        </span>
                        <span className="rounded-full px-2 py-0.5 text-xs font-medium border border-red-200 bg-white text-red-700">
                          {plugin.trust_level}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
                <p className="text-xs text-red-700 font-medium">
                  Quarantined due to potential security or policy violation. All permissions suspended.
                </p>
              </div>
              <div className="pt-3 border-t border-red-100 flex items-center justify-between">
                <StatusBadge state="Failed" detail="quarantined" />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ?? Page shell ????????????????????????????????????????????????????????????????

export function PluginsPage() {
  const [tab, setTab] = useState<Tab>('installed');

  const tabs: { id: Tab; label: string }[] = [
    { id: 'installed', label: 'Installed Plugins' },
    { id: 'quarantined', label: 'Quarantined' },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Plugin SDK</h1>
          <p className="text-sm text-slate-500">
            Manage third-party plugins. No plugin receives implicit privilege. Permission escalation requires review.
          </p>
        </div>
      </div>

      <div className="flex gap-4 border-b border-slate-200">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`pb-2 text-sm font-medium border-b-2 transition-all ${tab === t.id ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500 hover:text-slate-800'}`}
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
