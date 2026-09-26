import { useCallback, useEffect, useState } from 'react';
import { goeyToast } from 'goey-toast';

import {
  containerApi,
  isStepUpRequired,
  type Container,
  type ContainerRegistry,
  type ContainerStack,
  type ContainerVolume,
  type Project,
  type Server,
} from '../api/client';
import { StepUpPrompt } from '../components/StepUpPrompt';
import {
  EmptyState,
  ErrorNote,
  Field,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
} from '../components/ui';

function formatTs(value: string | null | undefined): string {
  if (!value) return '-';
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
  const [servers, setServers] = useState<Server[]>([]);
  const [selectedContainer, setSelectedContainer] = useState<Container | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [stepUpPending, setStepUpPending] = useState(false);
  const [stepUpAction, setStepUpAction] = useState<(() => Promise<void>) | null>(null);
  const [tab, setTab] = useState<'containers' | 'catalog' | 'stacks' | 'registries' | 'volumes'>('containers');
  const [catalogCategory, setCatalogCategory] = useState<string>('all');
  const [installingApp, setInstallingApp] = useState<string | null>(null);
  const [installModalApp, setInstallModalApp] = useState<{ id: string; name: string; icon: string; port: string; yaml: string; desc: string } | null>(null);
  const [installName, setInstallName] = useState('');
  const [installYaml, setInstallYaml] = useState('');
  const [installServerId, setInstallServerId] = useState('');
  const [installPort, setInstallPort] = useState('');
  const [installPassword, setInstallPassword] = useState('');
  const [logs, setLogs] = useState<string[] | null>(null);
  const [logsLoading, setLogsLoading] = useState(false);
  const [showCreateRegistry, setShowCreateRegistry] = useState(false);
  const [newReg, setNewReg] = useState({ name: '', host: '', password: '' });
  const [lifecycleLoading, setLifecycleLoading] = useState<Record<string, boolean>>({});


  // Load projects and servers from the api endpoints via dynamic import.
  // ponytail: api object not imported directly — matches existing pattern
  useEffect(() => {
    import('../api/client').then(({ api }) => {
      api
        .listProjects()
        .then((r) => {
          setProjects(r.projects ?? []);
          if (r.projects?.length) setSelectedProject(r.projects[0]);
        })
        .catch((e: unknown) => setError(toError(e)));

      api
        .listServers()
        .then((r) => {
          setServers(r.servers ?? []);
          if (r.servers?.length) setInstallServerId(r.servers[0].id);
        })
        .catch(() => {});
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

  async function handleLifecycle(c: Container, action: 'start' | 'stop' | 'restart') {
    setLifecycleLoading((prev) => ({ ...prev, [c.id]: true }));
    setError(null);
    try {
      if (action === 'start') {
        await containerApi.startContainer(c.project_id, c.id);
      } else if (action === 'stop') {
        await containerApi.stopContainer(c.project_id, c.id);
      } else if (action === 'restart') {
        await containerApi.restartContainer(c.project_id, c.id);
      }
      loadData();
    } catch (e: unknown) {
      setError(toError(e));
    } finally {
      setLifecycleLoading((prev) => ({ ...prev, [c.id]: false }));
    }
  }

  const CATALOG_ITEMS = [
    { id: 'redis', name: 'Redis', icon: '⚡', category: 'cache', desc: 'In-memory data store - cache & message broker.', port: '6379', yaml: `version: "3"\nservices:\n  redis:\n    image: redis:7-alpine\n    restart: unless-stopped\n    ports:\n      - "6379:6379"\n    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru` },
    { id: 'mariadb', name: 'MariaDB', icon: '🐬', category: 'database', desc: 'Drop-in MySQL replacement with high performance.', port: '3306', yaml: `version: "3"\nservices:\n  mariadb:\n    image: mariadb:11\n    restart: unless-stopped\n    ports:\n      - "3306:3306"\n    environment:\n      MARIADB_ROOT_PASSWORD: changeme\n      MARIADB_DATABASE: app\n      MARIADB_USER: dbuser\n      MARIADB_PASSWORD: changeme` },
    { id: 'minio', name: 'MinIO', icon: '🪣', category: 'storage', desc: 'S3-compatible object storage with web console.', port: '9000', yaml: `version: "3"\nservices:\n  minio:\n    image: minio/minio:latest\n    restart: unless-stopped\n    command: server /data --console-address ":9001"\n    ports:\n      - "9000:9000"\n      - "9001:9001"\n    environment:\n      MINIO_ROOT_USER: minioadmin\n      MINIO_ROOT_PASSWORD: changeme` },
    { id: 'rabbitmq', name: 'RabbitMQ', icon: '🐇', category: 'cache', desc: 'Most widely deployed open-source message broker.', port: '5672', yaml: `version: "3"\nservices:\n  rabbitmq:\n    image: rabbitmq:3-management-alpine\n    restart: unless-stopped\n    ports:\n      - "5672:5672"\n      - "15672:15672"` },
    { id: 'meilisearch', name: 'Meilisearch', icon: '🔍', category: 'devtools', desc: 'Lightning-fast, hyper-relevant search engine.', port: '7700', yaml: `version: "3"\nservices:\n  meilisearch:\n    image: getmeili/meilisearch:latest\n    restart: unless-stopped\n    ports:\n      - "7700:7700"\n    environment:\n      MEILI_NO_ANALYTICS: "true"` },
    { id: 'wordpress', name: 'WordPress', icon: '📝', category: 'cms', desc: "World's most popular CMS platform.", port: '8080', yaml: `version: "3"\nservices:\n  wordpress:\n    image: wordpress:latest\n    restart: unless-stopped\n    ports:\n      - "8080:80"\n    environment:\n      WORDPRESS_DB_HOST: db\n      WORDPRESS_DB_USER: wp\n      WORDPRESS_DB_PASSWORD: changeme\n      WORDPRESS_DB_NAME: wordpress\n  db:\n    image: mariadb:11\n    restart: unless-stopped\n    environment:\n      MARIADB_DATABASE: wordpress\n      MARIADB_USER: wp\n      MARIADB_PASSWORD: changeme\n      MARIADB_ROOT_PASSWORD: changeme` },
    { id: 'n8n', name: 'n8n', icon: '🔄', category: 'devtools', desc: 'Fair-code workflow automation (Zapier alternative).', port: '5678', yaml: `version: "3"\nservices:\n  n8n:\n    image: n8nio/n8n:latest\n    restart: unless-stopped\n    ports:\n      - "5678:5678"\n    environment:\n      N8N_SECURE_COOKIE: "false"` },
    { id: 'uptime-kuma', name: 'Uptime Kuma', icon: '📊', category: 'devtools', desc: 'Self-hosted monitoring tool with a fancy UI.', port: '3001', yaml: `version: "3"\nservices:\n  uptime-kuma:\n    image: louislam/uptime-kuma:latest\n    restart: unless-stopped\n    ports:\n      - "3001:3001"\n    volumes:\n      - uptime-kuma-data:/app/data\nvolumes:\n  uptime-kuma-data:` },
  ];

  const CATALOG_CATEGORIES = ['all', 'database', 'cache', 'storage', 'cms', 'devtools'] as const;

  const STACK_NAME_RE = /^[a-z0-9][a-z0-9-]*$/;

  // Extract first host port mapping like "- \"6379:6379\"" → "6379"
  function extractPort(yaml: string): string {
    const m = yaml.match(/- ["']?(\d+):\d+["']?/);
    return m ? m[1] : '';
  }

  // Extract first "changeme" password value from YAML
  function extractPassword(yaml: string): string {
    const m = yaml.match(/(?:PASSWORD|ROOT_PASSWORD|ROOT_USER):\s*(\S+)/i);
    return m ? m[1] : '';
  }

  // Replace all host-port values in "- \"HOST:CONTAINER\"" lines
  function applyPort(yaml: string, oldPort: string, newPort: string): string {
    if (!oldPort || oldPort === newPort) return yaml;
    return yaml.replace(
      new RegExp(`(- ["']?)${oldPort}(:\\d+["']?)`, 'g'),
      `$1${newPort}$2`,
    );
  }

  // Replace occurrences of oldPw in YAML env values
  function applyPassword(yaml: string, oldPw: string, newPw: string): string {
    if (!oldPw || oldPw === newPw || !newPw) return yaml;
    return yaml.split(oldPw).join(newPw);
  }

  function openInstallModal(item: (typeof CATALOG_ITEMS)[number]) {
    const port = extractPort(item.yaml);
    const pw = extractPassword(item.yaml);
    setInstallModalApp(item);
    setInstallName(item.id + '-service');
    setInstallYaml(item.yaml);
    setInstallPort(port);
    setInstallPassword(pw);
  }

  function handleInstallPortChange(newPort: string) {
    setInstallYaml((prev) => applyPort(prev, installPort, newPort));
    setInstallPort(newPort);
  }

  function handleInstallPasswordChange(newPw: string) {
    setInstallYaml((prev) => applyPassword(prev, installPassword, newPw));
    setInstallPassword(newPw);
  }

  async function handleInstallFromCatalog() {
    if (!installModalApp || !selectedProject) return;
    const name = installName.trim();
    if (!name) {
      goeyToast.error('Stack name is required.');
      return;
    }
    if (!STACK_NAME_RE.test(name)) {
      goeyToast.error('Stack name must be lowercase alphanumeric and hyphens only (e.g. my-redis).');
      return;
    }
    const serverId = installServerId || servers[0]?.id;
    if (!serverId) {
      goeyToast.error('No server enrolled. Enroll a server first.');
      return;
    }
    setInstallingApp(installModalApp.id);
    try {
      await containerApi.createStack(selectedProject.id, {
        server_id: serverId,
        name,
        compose_yaml: installYaml,
      });
      goeyToast.success(`${installModalApp.name} deployed as stack "${name}"!`);
      setInstallModalApp(null);
      loadData();
      setTab('stacks');
    } catch (e: unknown) {
      goeyToast.error(toError(e).message);
    } finally {
      setInstallingApp(null);
    }
  }

  if (stepUpPending && stepUpAction) {
    return (
      <StepUpPrompt
        onElevated={async () => {
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
    <div className="space-y-6">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Containers</h1>
          <p className="text-sm text-slate-500">Manage Docker containers, compose stacks, and images.</p>
        </div>
        {loading && <span className="text-sm text-slate-400">Loading…</span>}
      </div>

      {error && <ErrorNote error={error} />}

      {/* Project selector */}
      {projects.length > 1 && (
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <label className="block text-sm font-medium text-slate-700 mb-1">Project</label>
          <select
            className="block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none max-w-xs"
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
        </div>
      )}

      {/* Privileged container warning */}
      {privileged.length > 0 && (
        <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800">
          <strong>Warning:</strong> {privileged.length} privileged container{privileged.length !== 1 ? 's' : ''} running in this project. Privileged containers have full host access.
          <ul className="mt-1 list-inside list-disc">
            {privileged.map((c) => (
              <li key={c.id}>{c.name}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-2 border-b border-slate-200">
        {(['containers', 'catalog', 'stacks', 'registries', 'volumes'] as const).map((t) => (
          <button
            key={t}
            className={`px-4 py-2 text-sm font-medium capitalize ${tab === t ? 'border-b-2 border-indigo-600 text-indigo-600' : 'text-slate-500 hover:text-slate-900'}`}
            onClick={() => setTab(t)}
          >
            {t === 'catalog' ? '🛒 App Store' : t}
          </button>
        ))}
      </div>

      {/* Containers tab */}
      {tab === 'containers' && (
        <div className="space-y-4">
          {containers.length === 0 ? (
            <div className="rounded-xl border border-slate-200 bg-white p-12 shadow-sm flex flex-col items-center gap-3 text-center">
              <span className="text-4xl">🐳</span>
              <h3 className="text-sm font-semibold text-slate-900">No containers</h3>
              <p className="text-sm text-slate-500">No containers are tracked in this project. Containers appear here when registered.</p>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Name</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Image</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Privileged</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Started</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {containers.map((c) => {
                    const pillColor =
                      c.state === 'running'
                        ? 'bg-emerald-50 text-emerald-700'
                        : c.state === 'exited' || c.state === 'dead'
                        ? 'bg-slate-100 text-slate-600'
                        : 'bg-amber-50 text-amber-700';
                    return (
                      <tr key={c.id} className="hover:bg-slate-50">
                        <td className="px-4 py-3 font-mono text-xs text-slate-900 font-medium">{c.name}</td>
                        <td className="px-4 py-3 text-xs text-slate-500">{c.image_ref}</td>
                        <td className="px-4 py-3">
                          <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${pillColor}`}>
                            {c.state}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          {c.privileged ? (
                            <span className="rounded-full bg-amber-50 px-2 py-0.5 text-xs font-medium text-amber-700">⚠ privileged</span>
                          ) : (
                            <span className="text-slate-400">-</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-500">{formatTs(c.started_at)}</td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1.5">
                            <button
                              className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-all"
                              onClick={() => openLogs(c)}
                            >
                              Logs
                            </button>
                            {c.state === 'running' ? (
                              <>
                                <button
                                  className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-all"
                                  disabled={lifecycleLoading[c.id]}
                                  onClick={() => handleLifecycle(c, 'restart')}
                                >
                                  {lifecycleLoading[c.id] ? '…' : 'Restart'}
                                </button>
                                <button
                                  className="rounded-lg bg-red-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-red-700 transition-all"
                                  disabled={lifecycleLoading[c.id]}
                                  onClick={() => handleLifecycle(c, 'stop')}
                                >
                                  {lifecycleLoading[c.id] ? '…' : 'Stop'}
                                </button>
                              </>
                            ) : (
                              <button
                                className="rounded-lg bg-indigo-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-indigo-700 transition-all"
                                disabled={lifecycleLoading[c.id]}
                                onClick={() => handleLifecycle(c, 'start')}
                              >
                                {lifecycleLoading[c.id] ? '…' : 'Start'}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Log viewer */}
          {selectedContainer && (
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold text-slate-900">Logs: {selectedContainer.name}</span>
                <button
                  className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-all"
                  onClick={() => { setSelectedContainer(null); setLogs(null); }}
                >
                  Close
                </button>
              </div>
              <pre className="max-h-64 overflow-y-auto rounded-lg bg-slate-900 p-4 font-mono text-xs text-slate-100 whitespace-pre-wrap">
                {logsLoading ? (
                  <span className="text-slate-400">Loading logs…</span>
                ) : logs && logs.length > 0 ? (
                  logs.map((line, i) => <div key={i}>{line}</div>)
                ) : (
                  <span className="text-slate-400">No log output.</span>
                )}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* App Catalog tab */}
      {tab === 'catalog' && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-base font-semibold text-ink">App Store - 1-Click Docker Catalog</h2>
              <p className="text-xs text-ink-secondary">Deploy popular software as isolated Docker compose stacks with one click.</p>
            </div>
            {/* Category Pills */}
            <div className="flex flex-wrap gap-1.5 text-xs">
              {CATALOG_CATEGORIES.map((cat) => (
                <button
                  key={cat}
                  onClick={() => setCatalogCategory(cat)}
                  className={`rounded-full px-3 py-1 font-medium capitalize transition ${
                    catalogCategory === cat
                      ? 'bg-accent text-white'
                      : 'border border-border bg-surface text-ink-secondary hover:border-accent hover:text-ink'
                  }`}
                >
                  {cat === 'all' ? 'All Apps' : cat}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {CATALOG_ITEMS.filter((item) => catalogCategory === 'all' || item.category === catalogCategory).map((item) => {
              const isInstalled = stacks.some((s) => s.name === item.id + '-service' || s.name === item.id);
              return (
                <div
                  key={item.id}
                  className="flex flex-col justify-between rounded-xl border border-border bg-surface p-5 shadow-sm transition hover:border-accent/40 hover:shadow-md"
                >
                  <div>
                    <div className="mb-3 flex items-start justify-between">
                      <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-border bg-elevated text-xl">
                        {item.icon}
                      </div>
                      <span className="rounded bg-elevated px-2 py-0.5 text-[10px] font-semibold text-ink-secondary">
                        Port :{item.port}
                      </span>
                    </div>
                    <h3 className="mb-1 text-sm font-bold text-ink">{item.name}</h3>
                    <p className="text-xs leading-relaxed text-ink-secondary">{item.desc}</p>
                  </div>
                  <div className="mt-4 flex items-center justify-between border-t border-border pt-3">
                    <span className="font-mono text-[10px] text-ink-muted">Docker Compose</span>
                    {isInstalled ? (
                      <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-xs font-semibold text-emerald-600">
                        ✓ Installed
                      </span>
                    ) : (
                      <button
                        className={primaryButtonClass}
                        disabled={installingApp === item.id}
                        onClick={() => openInstallModal(item)}
                      >
                        {installingApp === item.id ? 'Installing…' : 'Install'}
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Modal: Customize & Install */}
          {installModalApp && (() => {
            const nameVal = installName.trim();
            const nameInvalid = nameVal !== '' && !STACK_NAME_RE.test(nameVal);
            const canDeploy = !installingApp && !!nameVal && !nameInvalid && !!installServerId;
            return (
              <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-sm">
                <div className="w-full max-w-lg rounded-2xl border border-border bg-surface p-6 shadow-2xl">
                  <div className="mb-4 flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-border bg-elevated text-xl">
                      {installModalApp.icon}
                    </div>
                    <div>
                      <h3 className="text-base font-bold text-ink">Install {installModalApp.name}</h3>
                      <p className="text-xs text-ink-secondary">{installModalApp.desc}</p>
                    </div>
                  </div>

                  <div className="space-y-4 text-xs">
                    {/* Server selector */}
                    {servers.length > 0 ? (
                      <Field label="Target Server">
                        <select
                          className={inputClass}
                          value={installServerId}
                          onChange={(e) => setInstallServerId(e.target.value)}
                        >
                          {servers.map((s) => (
                            <option key={s.id} value={s.id}>
                              {s.name} ({s.address})
                            </option>
                          ))}
                        </select>
                      </Field>
                    ) : (
                      <p className="rounded bg-warning/10 px-3 py-2 text-xs text-warning-ink">
                        No servers enrolled. Enroll a server before deploying stacks.
                      </p>
                    )}

                    {/* Stack name with validation */}
                    <div>
                      <Field label="Stack Name">
                        <input
                          type="text"
                          value={installName}
                          onChange={(e) => setInstallName(e.target.value)}
                          className={inputClass}
                          placeholder="my-redis"
                          spellCheck={false}
                        />
                      </Field>
                      {nameInvalid && (
                        <p className="mt-1 text-[11px] text-danger">
                          Lowercase letters, numbers, and hyphens only. Must start with a letter or digit.
                        </p>
                      )}
                    </div>

                    {/* Port */}
                    {installPort && (
                      <Field label="Host Port">
                        <input
                          type="text"
                          value={installPort}
                          onChange={(e) => handleInstallPortChange(e.target.value)}
                          className={inputClass}
                          placeholder="e.g. 6379"
                        />
                      </Field>
                    )}

                    {/* Password */}
                    {installPassword && (
                      <Field label="Admin Password">
                        <input
                          type="text"
                          value={installPassword}
                          onChange={(e) => handleInstallPasswordChange(e.target.value)}
                          className={inputClass}
                          placeholder="changeme"
                          spellCheck={false}
                        />
                      </Field>
                    )}

                    <Field label="Docker Compose YAML">
                      <textarea
                        rows={7}
                        value={installYaml}
                        onChange={(e) => setInstallYaml(e.target.value)}
                        className={`${inputClass} font-mono text-[11px]`}
                      />
                    </Field>
                  </div>

                  <div className="mt-6 flex justify-end gap-2">
                    <button
                      className={secondaryButtonClass}
                      onClick={() => setInstallModalApp(null)}
                    >
                      Cancel
                    </button>
                    <button
                      className={primaryButtonClass}
                      disabled={!canDeploy}
                      onClick={handleInstallFromCatalog}
                    >
                      {installingApp ? 'Deploying…' : 'Deploy Stack'}
                    </button>
                  </div>
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* Stacks tab */}
      {tab === 'stacks' && (
        <div className="space-y-4">
          {stacks.length === 0 ? (
            <div className="rounded-xl border border-slate-200 bg-white p-12 shadow-sm flex flex-col items-center gap-3 text-center">
              <span className="text-4xl">📦</span>
              <h3 className="text-sm font-semibold text-slate-900">No compose stacks</h3>
              <p className="text-sm text-slate-500">No compose stacks registered for this project.</p>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Name</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">State</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Created</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {stacks.map((s) => {
                    const stackPill =
                      s.state === 'running' ? 'bg-emerald-50 text-emerald-700' :
                      s.state === 'stopped' ? 'bg-slate-100 text-slate-600' :
                      'bg-amber-50 text-amber-700';
                    return (
                      <tr key={s.id} className="hover:bg-slate-50">
                        <td className="px-4 py-3 font-medium text-slate-900">{s.name}</td>
                        <td className="px-4 py-3">
                          <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${stackPill}`}>{s.state}</span>
                        </td>
                        <td className="px-4 py-3 text-sm text-slate-800">{formatTs(s.created_at)}</td>
                      </tr>
                    );
                  })}
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
                        {v.size_bytes != null ? `${(v.size_bytes / 1024 / 1024).toFixed(1)} MB` : '-'}
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
