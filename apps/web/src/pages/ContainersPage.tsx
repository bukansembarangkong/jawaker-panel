import { useCallback, useEffect, useState } from 'react';

import {
  containerApi,
  isStepUpRequired,
  type Container,
  type ContainerRegistry,
  type ContainerStack,
  type ContainerVolume,
  type Project,
} from '../api/client';
import { StepUpPrompt } from '../components/StepUpPrompt';
import {
  EmptyState,
  ErrorNote,
  Field,
  StatusBadge,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
  type OperationalState,
} from '../components/ui';

function mapContainerState(c: Container): OperationalState {
  if (c.state === 'running') return c.health === 'healthy' || c.health === 'none' ? 'Healthy' : 'Warning';
  if (c.state === 'paused') return 'Warning';
  if (c.state === 'exited' || c.state === 'dead') return 'Disabled';
  return 'Disabled';
}

function formatTs(value: string | null | undefined): string {
  if (!value) return '—';
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function toError(e: unknown): Error {
  return e instanceof Error ? e : new Error(String(e));
}

export function ContainersPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [containers, setContainers] = useState<Container[]>([]);
  const [privileged, setPrivileged] = useState<Container[]>([]);
  const [stacks, setStacks] = useState<ContainerStack[]>([]);
  const [registries, setRegistries] = useState<ContainerRegistry[]>([]);
  const [volumes, setVolumes] = useState<ContainerVolume[]>([]);
  const [selectedContainer, setSelectedContainer] = useState<Container | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [stepUpPending, setStepUpPending] = useState(false);
  const [stepUpAction, setStepUpAction] = useState<(() => Promise<void>) | null>(null);
  const [tab, setTab] = useState<'containers' | 'stacks' | 'registries' | 'volumes'>('containers');
  const [logs, setLogs] = useState<string[] | null>(null);
  const [logsLoading, setLogsLoading] = useState(false);
  const [showCreateRegistry, setShowCreateRegistry] = useState(false);
  const [newReg, setNewReg] = useState({ name: '', host: '', password: '' });

  // Load projects from the api.listProjects endpoint via the existing api object.
  // ponytail: api object not imported here — use the same import pattern as DatabasesPage
  useEffect(() => {
    import('../api/client').then(({ api }) => {
      api
        .listProjects()
        .then((r) => {
          setProjects(r.projects ?? []);
          if (r.projects?.length) setSelectedProject(r.projects[0]);
        })
        .catch((e: unknown) => setError(toError(e)));
    });
  }, []);

  const loadData = useCallback(() => {
    if (!selectedProject) return;
    setLoading(true);
    setError(null);
    const pid = selectedProject.id;
    Promise.all([
      containerApi.listContainers(pid),
      containerApi.listPrivilegedContainers(pid),
      containerApi.listStacks(pid),
      containerApi.listRegistries(pid),
      containerApi.listVolumes(pid),
    ])
      .then(([cs, priv, ss, rs, vs]) => {
        setContainers(cs.containers ?? []);
        setPrivileged(priv.containers ?? []);
        setStacks(ss.stacks ?? []);
        setRegistries(rs.registries ?? []);
        setVolumes(vs.volumes ?? []);
      })
      .catch((e: unknown) => setError(toError(e)))
      .finally(() => setLoading(false));
  }, [selectedProject]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  function openLogs(c: Container) {
    setSelectedContainer(c);
    setLogs(null);
    setLogsLoading(true);
    containerApi
      .getContainerLogs(c.project_id, c.id)
      .then((r) => setLogs(r.lines))
      .catch((e: unknown) => setLogs([`Error: ${toError(e).message}`]))
      .finally(() => setLogsLoading(false));
  }

  async function handleDeleteRegistry(id: string) {
    if (!selectedProject) return;
    const run = async () => {
      await containerApi.deleteRegistry(selectedProject.id, id);
      loadData();
    };
    try {
      await run();
    } catch (e: unknown) {
      if (isStepUpRequired(e)) {
        setStepUpAction(() => run);
        setStepUpPending(true);
      } else {
        setError(toError(e));
      }
    }
  }

  async function handleCreateRegistry() {
    if (!selectedProject) return;
    const run = async () => {
      await containerApi.createRegistry(selectedProject.id, {
        name: newReg.name,
        host: newReg.host,
        password: newReg.password || undefined,
      });
      setShowCreateRegistry(false);
      setNewReg({ name: '', host: '', password: '' });
      loadData();
    };
    try {
      await run();
    } catch (e: unknown) {
      if (isStepUpRequired(e)) {
        setStepUpAction(() => run);
        setStepUpPending(true);
      } else {
        setError(toError(e));
      }
    }
  }

  if (stepUpPending && stepUpAction) {
    return (
      <StepUpPrompt
        onSuccess={async () => {
          setStepUpPending(false);
          await stepUpAction();
          setStepUpAction(null);
        }}
        onCancel={() => {
          setStepUpPending(false);
          setStepUpAction(null);
        }}
      />
    );
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-ink">Containers</h1>
        {loading && <span className="text-sm text-ink-secondary">Loading…</span>}
      </div>

      {error && <ErrorNote error={error} />}

      {/* Project selector */}
      {projects.length > 1 && (
        <Field label="Project">
          <select
            className={inputClass}
            value={selectedProject?.id ?? ''}
            onChange={(e) => {
              const p = projects.find((x) => x.id === e.target.value) ?? null;
              setSelectedProject(p);
              setSelectedContainer(null);
              setLogs(null);
            }}
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </Field>
      )}

      {/* Privileged container warning */}
      {privileged.length > 0 && (
        <div className="rounded-md border border-warning bg-warning/10 px-4 py-3 text-sm text-warning-ink">
          <strong>Warning:</strong> {privileged.length} privileged container{privileged.length !== 1 ? 's' : ''} running in this project. Privileged containers have full host access.
          <ul className="mt-1 list-inside list-disc">
            {privileged.map((c) => (
              <li key={c.id}>{c.name}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-2 border-b border-border">
        {(['containers', 'stacks', 'registries', 'volumes'] as const).map((t) => (
          <button
            key={t}
            className={`px-4 py-2 text-sm font-medium capitalize ${tab === t ? 'border-b-2 border-accent text-accent' : 'text-ink-secondary hover:text-ink'}`}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Containers tab */}
      {tab === 'containers' && (
        <div className="space-y-4">
          {containers.length === 0 ? (
            <EmptyState title="No containers">
              <p className="text-sm text-ink-secondary">No containers are tracked in this project. Containers appear here when they are registered with the platform.</p>
            </EmptyState>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full text-sm">
                <thead className="bg-elevated text-xs font-medium uppercase text-ink-secondary">
                  <tr>
                    <th className="px-4 py-3 text-left">Name</th>
                    <th className="px-4 py-3 text-left">Image</th>
                    <th className="px-4 py-3 text-left">State</th>
                    <th className="px-4 py-3 text-left">Privileged</th>
                    <th className="px-4 py-3 text-left">Started</th>
                    <th className="px-4 py-3 text-left">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {containers.map((c) => (
                    <tr key={c.id} className="hover:bg-elevated/50">
                      <td className="px-4 py-3 font-mono text-xs">{c.name}</td>
                      <td className="px-4 py-3 text-ink-secondary">{c.image_ref}</td>
                      <td className="px-4 py-3">
                        <StatusBadge state={mapContainerState(c)} detail={c.state} />
                      </td>
                      <td className="px-4 py-3">
                        {c.privileged ? (
                          <span className="rounded bg-warning/20 px-1.5 py-0.5 text-xs font-medium text-warning-ink">⚠ privileged</span>
                        ) : (
                          <span className="text-ink-muted">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-ink-secondary">{formatTs(c.started_at)}</td>
                      <td className="px-4 py-3">
                        <button
                          className={secondaryButtonClass}
                          onClick={() => openLogs(c)}
                        >
                          Logs
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Log viewer */}
          {selectedContainer && (
            <div className="rounded-lg border border-border bg-elevated">
              <div className="flex items-center justify-between border-b border-border px-4 py-2">
                <span className="text-sm font-medium text-ink">Logs: {selectedContainer.name}</span>
                <button
                  className="text-xs text-ink-secondary hover:text-ink"
                  onClick={() => { setSelectedContainer(null); setLogs(null); }}
                >
                  Close
                </button>
              </div>
              <div className="max-h-64 overflow-y-auto p-4 font-mono text-xs text-ink">
                {logsLoading ? (
                  <span className="text-ink-secondary">Loading logs…</span>
                ) : logs && logs.length > 0 ? (
                  logs.map((line, i) => <div key={i}>{line}</div>)
                ) : (
                  <span className="text-ink-secondary">No log output.</span>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Stacks tab */}
      {tab === 'stacks' && (
        <div>
          {stacks.length === 0 ? (
            <EmptyState title="No compose stacks">
              <p className="text-sm text-ink-secondary">No compose stacks registered for this project.</p>
            </EmptyState>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full text-sm">
                <thead className="bg-elevated text-xs font-medium uppercase text-ink-secondary">
                  <tr>
                    <th className="px-4 py-3 text-left">Name</th>
                    <th className="px-4 py-3 text-left">State</th>
                    <th className="px-4 py-3 text-left">Created</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {stacks.map((s) => (
                    <tr key={s.id} className="hover:bg-elevated/50">
                      <td className="px-4 py-3 font-medium text-ink">{s.name}</td>
                      <td className="px-4 py-3 text-ink-secondary">{s.state}</td>
                      <td className="px-4 py-3 text-ink-secondary">{formatTs(s.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Registries tab */}
      {tab === 'registries' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button
              className={primaryButtonClass}
              onClick={() => setShowCreateRegistry(true)}
            >
              Add registry
            </button>
          </div>

          {showCreateRegistry && (
            <div className="rounded-lg border border-border p-4">
              <h3 className="mb-4 text-sm font-semibold text-ink">Add container registry</h3>
              <div className="space-y-3">
                <Field label="Name">
                  <input
                    className={inputClass}
                    value={newReg.name}
                    onChange={(e) => setNewReg({ ...newReg, name: e.target.value })}
                    placeholder="my-registry"
                  />
                </Field>
                <Field label="Host">
                  <input
                    className={inputClass}
                    value={newReg.host}
                    onChange={(e) => setNewReg({ ...newReg, host: e.target.value })}
                    placeholder="registry.example.com"
                  />
                </Field>
                <Field label="Password / token (optional)">
                  <input
                    type="password"
                    className={inputClass}
                    value={newReg.password}
                    onChange={(e) => setNewReg({ ...newReg, password: e.target.value })}
                    placeholder="Leave empty for public registries"
                  />
                </Field>
                <div className="flex gap-2">
                  <button className={primaryButtonClass} onClick={handleCreateRegistry}>
                    Save
                  </button>
                  <button
                    className={secondaryButtonClass}
                    onClick={() => { setShowCreateRegistry(false); setNewReg({ name: '', host: '', password: '' }); }}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          )}

          {registries.length === 0 ? (
            <EmptyState title="No registries">
              <p className="text-sm text-ink-secondary">Add a container registry to pull images from private repositories.</p>
            </EmptyState>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full text-sm">
                <thead className="bg-elevated text-xs font-medium uppercase text-ink-secondary">
                  <tr>
                    <th className="px-4 py-3 text-left">Name</th>
                    <th className="px-4 py-3 text-left">Host</th>
                    <th className="px-4 py-3 text-left">Credential</th>
                    <th className="px-4 py-3 text-left">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {registries.map((r) => (
                    <tr key={r.id} className="hover:bg-elevated/50">
                      <td className="px-4 py-3 font-medium text-ink">{r.name}</td>
                      <td className="px-4 py-3 font-mono text-xs text-ink-secondary">{r.host}</td>
                      <td className="px-4 py-3">
                        {r.has_credential ? (
                          <span className="rounded bg-accent/10 px-1.5 py-0.5 text-xs text-accent">sealed</span>
                        ) : (
                          <span className="text-ink-muted">none</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <button
                          className="text-xs text-danger hover:underline"
                          onClick={() => handleDeleteRegistry(r.id)}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Volumes tab */}
      {tab === 'volumes' && (
        <div>
          {volumes.length === 0 ? (
            <EmptyState title="No volumes">
              <p className="text-sm text-ink-secondary">No volumes tracked for this project.</p>
            </EmptyState>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full text-sm">
                <thead className="bg-elevated text-xs font-medium uppercase text-ink-secondary">
                  <tr>
                    <th className="px-4 py-3 text-left">Name</th>
                    <th className="px-4 py-3 text-left">Driver</th>
                    <th className="px-4 py-3 text-left">Mount point</th>
                    <th className="px-4 py-3 text-left">Size</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {volumes.map((v) => (
                    <tr key={v.id} className="hover:bg-elevated/50">
                      <td className="px-4 py-3 font-medium text-ink">{v.name}</td>
                      <td className="px-4 py-3 text-ink-secondary">{v.driver}</td>
                      <td className="px-4 py-3 font-mono text-xs text-ink-secondary">{v.mount_point}</td>
                      <td className="px-4 py-3 text-ink-secondary">
                        {v.size_bytes != null ? `${(v.size_bytes / 1024 / 1024).toFixed(1)} MB` : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
