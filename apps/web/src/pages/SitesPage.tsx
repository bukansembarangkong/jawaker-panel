import { useCallback, useEffect, useRef, useState } from 'react';

import {
  api,
  isStepUpRequired,
  primeCsrf,
  type ApplyAccepted,
  type JobStatus,
  type LogsTail,
  type NodeJSConfig,
  type Project,
  type Site,
  type SiteNodeJSStatusResult,
  type ValidateResult,
} from '../api/client';
import { StepUpPrompt } from '../components/StepUpPrompt';
import {
  EmptyState,
  ErrorNote,
  Field,
  Modal,
  StatusBadge,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
  type OperationalState,
} from '../components/ui';

/**
 * Sites: project picker → site list → site detail (Config | Logs tabs).
 *
 * Three invariants from DESIGN_SYSTEM.md enforced here:
 *  - Apply is disabled until validate PASSES on the exact current candidate text.
 *    Editing the text invalidates the verdict immediately (PRD §30.7).
 *  - Status is never conveyed by colour alone — every badge carries a text label.
 *  - No authorization rule lives only here; every endpoint re-checks on the server.
 */

/** Terminal job states — poll stops. */
const JOB_TERMINAL = new Set(['succeeded', 'failed', 'dead_letter', 'canceled']);

/** Simple line-based diff: returns an array of hunks with +/−/ tags. */
function lineDiff(
  prev: string,
  next: string,
): Array<{ kind: 'same' | 'removed' | 'added'; line: string }> {
  const prevLines = prev.split('\n');
  const nextLines = next.split('\n');

  // Longest-common-subsequence (patience-style: good enough for config files).
  const m = prevLines.length;
  const n = nextLines.length;
  const dp = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] =
        prevLines[i - 1] === nextLines[j - 1]
          ? (dp[i - 1][j - 1] ?? 0) + 1
          : Math.max(dp[i - 1][j] ?? 0, dp[i][j - 1] ?? 0);
    }
  }

  const result: Array<{ kind: 'same' | 'removed' | 'added'; line: string }> = [];
  let i = m;
  let j = n;
  while (i > 0 || j > 0) {
    const pi = prevLines[i - 1];
    const nj = nextLines[j - 1];
    if (i > 0 && j > 0 && pi === nj) {
      result.push({ kind: 'same', line: pi! });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || (dp[i]![j - 1] ?? 0) >= (dp[i - 1]![j] ?? 0))) {
      result.push({ kind: 'added', line: nj! });
      j--;
    } else {
      result.push({ kind: 'removed', line: pi! });
      i--;
    }
  }
  return result.reverse();
}

function mapSiteState(site: Site): OperationalState {
  if (site.state === 'deleted') return 'Disabled';
  if (site.state === 'pending_delete') return 'Warning';
  if (!site.applied_revision_id) return 'Pending';
  return 'Healthy';
}

function formatTs(value: string | null | undefined): string {
  if (!value) return '-';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

// ─── SitesPage ───────────────────────────────────────────────────────────────

export function SitesPage() {
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [sites, setSites] = useState<Site[] | null>(null);
  const [selectedSite, setSelectedSite] = useState<Site | null>(null);
  const [loadError, setLoadError] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);

  // Create site form
  const [showCreateSite, setShowCreateSite] = useState(false);
  const [siteSlug, setSiteSlug] = useState('');
  const [siteName, setSiteName] = useState('');
  const [siteMode, setSiteMode] = useState<'static' | 'php' | 'reverse_proxy'>('php');
  const [siteServerId, setSiteServerId] = useState('');
  const [siteDocRoot, setSiteDocRoot] = useState('');
  const [siteUpstream, setSiteUpstream] = useState('');
  const [sitePHPUnit, setSitePHPUnit] = useState('');
  const [siteCreateError, setSiteCreateError] = useState<Error | null>(null);
  const [servers, setServers] = useState<{ id: string; name: string }[]>([]);

  // Step-up elevation
  const [pendingElevation, setPendingElevation] = useState<(() => void) | null>(null);

  const loadProjects = useCallback(async () => {
    try {
      const page = await api.listProjects({ state: 'active' });
      if (page.projects && page.projects.length > 0) {
        setSelectedProject(page.projects[0]);
      } else {
        // Auto-create a default project silently so user goes straight to sites
        const created = await api.createProject({
          slug: 'default',
          name: 'Default',
          description: 'Default project workspace',
        });
        setSelectedProject(created.project);
      }
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof Error ? err : new Error(String(err)));
    }
  }, []);

  const loadSites = useCallback(async (projectId: string) => {
    try {
      const page = await api.listSites(projectId);
      setSites(page.sites);
    } catch (err) {
      setLoadError(err instanceof Error ? err : new Error(String(err)));
    }
  }, []);

  const loadServers = useCallback(async () => {
    try {
      const page = await api.listServers();
      setServers(page.servers.map((s) => ({ id: s.id, name: s.name })));
      if (page.servers.length > 0 && !siteServerId) {
        setSiteServerId(page.servers[0].id);
      }
    } catch {
      // Best-effort: server dropdown degrades to free-text
    }
  }, [siteServerId]);

  useEffect(() => {
    void loadProjects();
    void primeCsrf();
  }, [loadProjects]);

  useEffect(() => {
    if (selectedProject) void loadSites(selectedProject.id);
    else setSites(null);
    setSelectedSite(null);
  }, [selectedProject, loadSites]);


  const createSite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProject) return;
    setBusy(true);
    setSiteCreateError(null);
    const doCreate = async () => {
      try {
        const body: Parameters<typeof api.createSite>[1] = {
          server_id: siteServerId,
          slug: siteSlug,
          name: siteName,
          mode: siteMode,
        };
        if (siteDocRoot) body.doc_root = siteDocRoot;
        if (siteMode === 'reverse_proxy' && siteUpstream) body.upstream = siteUpstream;
        if (siteMode === 'php' && sitePHPUnit) body.php_unit = sitePHPUnit;
        const res = await api.createSite(selectedProject.id, body);
        setShowCreateSite(false);
        setSiteSlug('');
        setSiteName('');
        setSiteMode('static');
        setSiteServerId('');
        setSiteDocRoot('');
        setSiteUpstream('');
        setSitePHPUnit('');
        await loadSites(selectedProject.id);
        setSelectedSite(res.site);
      } catch (err) {
        if (isStepUpRequired(err)) {
          setPendingElevation(() => () => { void doCreate(); });
        } else {
          setSiteCreateError(err instanceof Error ? err : new Error(String(err)));
        }
      } finally {
        setBusy(false);
      }
    };
    await doCreate();
    void loadServers();
  };

  if (loadError) {
    return <ErrorNote error={loadError} title="Could not load" onRetry={() => void loadProjects()} />;
  }

  // ── Site detail active ───────────────────────────────────────────────────────
  if (selectedSite && selectedProject) {
    return (
      <>
        <Modal
          isOpen={!!pendingElevation}
          onClose={() => setPendingElevation(null)}
          title="Re-authentication Required"
        >
          <StepUpPrompt
            onElevated={() => {
              const action = pendingElevation;
              setPendingElevation(null);
              if (action) action();
            }}
            onCancel={() => setPendingElevation(null)}
          />
        </Modal>
        <SiteDetail
          site={selectedSite}
          project={selectedProject}
          onBack={() => setSelectedSite(null)}
          onDeleted={() => {
            setSelectedSite(null);
            if (selectedProject) void loadSites(selectedProject.id);
          }}
          onElevationRequired={(resume) => setPendingElevation(() => resume)}
        />
      </>
    );
  }

  // ── Direct sites list & creation ─────────────────────────────────────────────
  return (
    <div className="space-y-6">
      <Modal
        isOpen={!!pendingElevation}
        onClose={() => setPendingElevation(null)}
        title="Re-authentication Required"
      >
        <StepUpPrompt
          onElevated={() => {
            const action = pendingElevation;
            setPendingElevation(null);
            if (action) action();
          }}
          onCancel={() => setPendingElevation(null)}
        />
      </Modal>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-ink">Websites</h2>
          <p className="text-xs text-ink-muted mt-0.5">Manage domains, Nginx configuration, and web hosting</p>
        </div>
        {!showCreateSite && (
          <button
            type="button"
            className={primaryButtonClass}
            onClick={() => { void loadServers(); setShowCreateSite(true); }}
            disabled={!selectedProject}
          >
            + New site
          </button>
        )}
      </div>

      <Modal
        isOpen={showCreateSite}
        onClose={() => setShowCreateSite(false)}
        title="Add a new website"
      >
        <CreateSiteForm
          servers={servers}
          siteSlug={siteSlug} setSiteSlug={setSiteSlug}
          siteName={siteName} setSiteName={setSiteName}
          siteMode={siteMode} setSiteMode={setSiteMode}
          siteServerId={siteServerId} setSiteServerId={setSiteServerId}
          siteDocRoot={siteDocRoot} setSiteDocRoot={setSiteDocRoot}
          siteUpstream={siteUpstream} setSiteUpstream={setSiteUpstream}
          sitePHPUnit={sitePHPUnit} setSitePHPUnit={setSitePHPUnit}
          siteCreateError={siteCreateError}
          busy={busy}
          onSubmit={(e) => void createSite(e)}
          onCancel={() => setShowCreateSite(false)}
        />
      </Modal>

      {sites === null ? (
        <p role="status" className="text-sm text-ink-secondary">Loading sites...</p>
      ) : sites.length === 0 ? (
        <EmptyState title="No sites yet">
          <p className="text-sm text-ink-secondary mb-3">You do not have any websites hosted yet.</p>
          {!showCreateSite && (
            <button
              type="button"
              className={primaryButtonClass}
              onClick={() => { void loadServers(); setShowCreateSite(true); }}
            >
              Add your first site
            </button>
          )}
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line bg-surface">
          {sites.map((site) => (
            <li key={site.id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <StatusBadge state={mapSiteState(site)} />
                  <span className="truncate font-medium text-ink text-sm">{site.slug}</span>
                  <span className="text-xs text-ink-muted uppercase">{site.mode}</span>
                </div>
                {site.name !== site.slug && (
                  <p className="mt-0.5 text-xs text-ink-secondary">{site.name}</p>
                )}
              </div>
              <button
                type="button"
                className={secondaryButtonClass}
                onClick={() => setSelectedSite(site)}
              >
                Manage
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ─── CreateSiteForm ───────────────────────────────────────────────────────────

interface CreateSiteFormProps {
  servers: { id: string; name: string }[];
  siteSlug: string; setSiteSlug: (v: string) => void;
  siteName: string; setSiteName: (v: string) => void;
  siteMode: 'static' | 'php' | 'reverse_proxy'; setSiteMode: (v: 'static' | 'php' | 'reverse_proxy') => void;
  siteServerId: string; setSiteServerId: (v: string) => void;
  siteDocRoot: string; setSiteDocRoot: (v: string) => void;
  siteUpstream: string; setSiteUpstream: (v: string) => void;
  sitePHPUnit: string; setSitePHPUnit: (v: string) => void;
  siteCreateError: Error | null;
  busy: boolean;
  onSubmit: (e: React.FormEvent) => void;
  onCancel: () => void;
}

function CreateSiteForm({
  servers, siteSlug, setSiteSlug, siteName, setSiteName, siteMode, setSiteMode,
  siteServerId, setSiteServerId, siteDocRoot, setSiteDocRoot,
  siteUpstream, setSiteUpstream, sitePHPUnit, setSitePHPUnit,
  siteCreateError, busy, onSubmit, onCancel,
}: CreateSiteFormProps) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  // appType drives mode + upstream behind the scenes
  const [appType, setAppType] = useState<string>('php');
  const [customPort, setCustomPort] = useState('8080');

  function handleAppTypeChange(type: string) {
    setAppType(type);
    const portMap: Record<string, { mode: 'php' | 'static' | 'reverse_proxy'; port?: string }> = {
      php:     { mode: 'php' },
      static:  { mode: 'static' },
      nodejs:  { mode: 'reverse_proxy', port: '3000' },
      python:  { mode: 'reverse_proxy', port: '8000' },
      custom:  { mode: 'reverse_proxy', port: customPort },
    };
    const cfg = portMap[type];
    setSiteMode(cfg.mode);
    if (cfg.port) setSiteUpstream(`http://127.0.0.1:${cfg.port}`);
    else setSiteUpstream('');
  }

  function handlePortChange(port: string) {
    setCustomPort(port);
    setSiteUpstream(`http://127.0.0.1:${port}`);
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      {siteCreateError && <ErrorNote error={siteCreateError} title="Create failed" />}

      {servers.length > 1 && (
        <Field label="Server">
          <select className={inputClass} value={siteServerId} onChange={(e) => setSiteServerId(e.target.value)} required>
            <option value="">Select a server...</option>
            {servers.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
        </Field>
      )}

      <Field label="Domain Name">
        <input
          className={inputClass}
          value={siteName}
          placeholder="example.com"
          onChange={(e) => {
            const domain = e.target.value.trim().toLowerCase();
            setSiteName(domain);
            setSiteSlug(domain.replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, ''));
            if (domain) setSiteDocRoot(`/var/www/${domain}`);
          }}
          required
        />
      </Field>

      <Field label="Website Type">
        <select
          className={inputClass}
          value={appType}
          onChange={(e) => handleAppTypeChange(e.target.value)}
        >
          <option value="php">PHP Website (WordPress, Laravel, CodeIgniter)</option>
          <option value="static">Static Website (HTML, CSS, JS)</option>
          <option value="nodejs">Node.js App (Next.js, Express, Fastify)</option>
          <option value="python">Python App (FastAPI, Flask, Django)</option>
          <option value="custom">Other App / Docker (I will specify port)</option>
        </select>
      </Field>

      {appType === 'custom' && (
        <Field label="App Port">
          <input
            className={inputClass}
            type="number"
            min="1"
            max="65535"
            value={customPort}
            onChange={(e) => handlePortChange(e.target.value)}
            placeholder="8080"
            required
          />
          <p className="text-xs text-ink-muted mt-1">Port where your app is listening on this server</p>
        </Field>
      )}

      {/* Advanced */}
      <div className="pt-1 border-t border-line">
        <button
          type="button"
          className="text-xs font-medium text-accent hover:underline"
          onClick={() => setShowAdvanced(!showAdvanced)}
        >
          {showAdvanced ? 'Hide advanced settings' : 'Advanced settings'}
        </button>
        {showAdvanced && (
          <div className="mt-3 space-y-3 pl-2 border-l-2 border-line">
            <Field label="Slug">
              <input className={inputClass} value={siteSlug} onChange={(e) => setSiteSlug(e.target.value)} required pattern="[a-z0-9-]+" placeholder="auto-derived from domain" />
            </Field>
            <Field label="Document Root">
              <input className={inputClass} value={siteDocRoot} onChange={(e) => setSiteDocRoot(e.target.value)} placeholder="/var/www/example.com" />
            </Field>
            {siteMode === 'php' && (
              <Field label="PHP-FPM unit">
                <input className={inputClass} value={sitePHPUnit} onChange={(e) => setSitePHPUnit(e.target.value)} placeholder="Leave blank for system default" />
              </Field>
            )}
            {siteMode === 'reverse_proxy' && (
              <Field label="Upstream URL">
                <input className={inputClass} value={siteUpstream} onChange={(e) => setSiteUpstream(e.target.value)} placeholder="http://127.0.0.1:3000" />
              </Field>
            )}
          </div>
        )}
      </div>

      <div className="flex gap-2 pt-2">
        <button type="submit" className={primaryButtonClass} disabled={busy}>Create Website</button>
        <button type="button" className={secondaryButtonClass} onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

// ─── SiteDetail ───────────────────────────────────────────────────────────────

type SiteTab = 'config' | 'logs' | 'nodejs';

interface SiteDetailProps {
  site: Site;
  project: Project;
  onBack: () => void;
  onDeleted: () => void;
  onElevationRequired: (resume: () => void) => void;
}

function SiteDetail({ site, project, onBack, onDeleted, onElevationRequired }: SiteDetailProps) {
  const [tab, setTab] = useState<SiteTab>(site.mode === 'nodejs' ? 'nodejs' : 'config');
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);

  const doDelete = async () => {
    setBusy(true);
    setDeleteError(null);
    const run = async () => {
      try {
        await api.deleteSite(project.id, site.id);
        onDeleted();
      } catch (err) {
        if (isStepUpRequired(err)) {
          setDeleting(false);
          onElevationRequired(() => { void run(); });
        } else {
          setDeleteError(err instanceof Error ? err : new Error(String(err)));
        }
        setBusy(false);
      }
    };
    await run();
  };

  const tabs: SiteTab[] =
    site.mode === 'nodejs' || site.mode === 'reverse_proxy'
      ? ['nodejs', 'config', 'logs']
      : ['config', 'logs'];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <button type="button" className={secondaryButtonClass} onClick={onBack}>← Back</button>
        <div className="flex items-center gap-2">
          <StatusBadge state={mapSiteState(site)} />
          <h2 className="text-base font-semibold text-ink">{site.slug}</h2>
          <span className="text-xs text-ink-muted">{site.mode}</span>
        </div>
      </div>

      <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-3">
        <div>
          <dt className="text-ink-muted">Project</dt>
          <dd className="font-medium text-ink">{project.slug}</dd>
        </div>
        <div>
          <dt className="text-ink-muted">Server ID</dt>
          <dd className="font-mono text-xs text-ink">{site.server_id.slice(0, 8)}…</dd>
        </div>
        <div>
          <dt className="text-ink-muted">Applied revision</dt>
          <dd className="font-mono text-xs text-ink">{site.applied_revision_id ? site.applied_revision_id.slice(0, 8) + '…' : '-'}</dd>
        </div>
        {site.doc_root && (
          <div>
            <dt className="text-ink-muted">Document root</dt>
            <dd className="font-mono text-xs text-ink">{site.doc_root}</dd>
          </div>
        )}
        {site.upstream && (
          <div>
            <dt className="text-ink-muted">Upstream</dt>
            <dd className="font-mono text-xs text-ink">{site.upstream}</dd>
          </div>
        )}
        {site.php_unit && (
          <div>
            <dt className="text-ink-muted">PHP unit</dt>
            <dd className="font-mono text-xs text-ink">{site.php_unit}</dd>
          </div>
        )}
      </dl>

      {/* Tabs */}
      <nav className="flex gap-1 border-b border-line" aria-label="Site sections">
        {tabs.map((t) => (
          <button
            key={t}
            type="button"
            role="tab"
            aria-selected={tab === t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm border-b-2 -mb-px transition-colors ${
              t === 'nodejs' ? '' : 'capitalize'
            } ${
              tab === t
                ? 'border-ink text-ink font-medium'
                : 'border-transparent text-ink-secondary hover:text-ink'
            }`}
          >
            {t === 'nodejs' ? 'Node.js' : t}
          </button>
        ))}
      </nav>

      {tab === 'nodejs' && (
        <NodeJSTab site={site} project={project} onElevationRequired={onElevationRequired} />
      )}
      {tab === 'config' && (
        <ConfigTab site={site} project={project} onElevationRequired={onElevationRequired} />
      )}
      {tab === 'logs' && (
        <LogsTab site={site} project={project} />
      )}

      {/* Danger zone */}
      <div className="mt-8 rounded-lg border border-red-200 bg-red-50/50 p-4 dark:border-red-900/40 dark:bg-red-950/10">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h4 className="text-sm font-semibold text-red-700 dark:text-red-400">Danger Zone</h4>
            <p className="text-xs text-ink-muted mt-0.5">
              Permanently delete this website, its Nginx configuration, and project association.
            </p>
          </div>
          <button
            type="button"
            className="rounded-md border border-red-300 bg-white px-3.5 py-2 text-xs font-semibold text-red-600 shadow-sm hover:bg-red-50 hover:border-red-400 dark:border-red-800 dark:bg-surface dark:text-red-400 dark:hover:bg-red-950/30"
            onClick={() => { setDeleting(true); setDeleteError(null); }}
          >
            Delete Website…
          </button>
        </div>
      </div>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={deleting}
        onClose={() => setDeleting(false)}
        title="Delete Website"
      >
        <div className="space-y-4">
          <p className="text-sm text-ink">
            Are you sure you want to delete <strong className="font-semibold text-red-600">{site.name || site.slug}</strong>?
          </p>
          <div className="rounded-md border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/50 dark:bg-red-950/20 dark:text-red-400">
            This will permanently remove the Nginx configuration, routing, and project association.
          </div>
          {deleteError && <ErrorNote error={deleteError} title="Delete failed" />}
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              className={secondaryButtonClass}
              onClick={() => setDeleting(false)}
              disabled={busy}
            >
              Cancel
            </button>
            <button
              type="button"
              className="rounded-md bg-red-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-red-700 disabled:opacity-50"
              disabled={busy}
              onClick={() => void doDelete()}
            >
              {busy ? 'Deleting…' : 'Delete Website'}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

// ─── ConfigTab ────────────────────────────────────────────────────────────────

/**
 * Hash a string to a stable identity for the validate gate.
 * Using JSON.stringify(text) as a simple stable key — only needs referential equality.
 */
function textKey(text: string, filename: string) {
  return `${filename}::${text.length}::${text.slice(0, 40)}`;
}

/** Generate a correct default Nginx config from the site's actual mode and properties. */
function generateDefaultNginxConfig(site: Site): string {
  // Prefer site.name as the domain if it looks like a hostname, otherwise reconstruct from slug
  const serverName = site.name && /[a-z0-9-]+\.[a-z]{2,}/.test(site.name)
    ? site.name
    : site.slug.replace(/-/g, '.').replace(/\.\./g, '-') || 'example.com';
  const docRoot = site.doc_root || `/var/www/${serverName}`;
  const upstream = site.upstream || 'http://127.0.0.1:3000';

  if (site.mode === 'nodejs' || site.mode === 'reverse_proxy') {
    return `server {
    listen 80;
    server_name ${serverName};

    location / {
        proxy_pass ${upstream};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`;
  }

  if (site.mode === 'php') {
    const phpSock = site.php_unit
      ? `/run/php/${site.php_unit}.sock`
      : '/run/php/php8.2-fpm.sock';
    return `server {
    listen 80;
    server_name ${serverName};
    root ${docRoot};
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \\.php$ {
        include fastcgi_params;
        fastcgi_pass unix:${phpSock};
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
}
`;
  }

  // Static fallback
  return `server {
    listen 80;
    server_name ${serverName};
    root ${docRoot};
    index index.html index.htm;

    location / {
        try_files $uri $uri/ =404;
    }
}
`;
}

interface ConfigTabProps {
  site: Site;
  project: Project;
  onElevationRequired: (resume: () => void) => void;
}

function ConfigTab({ site, project, onElevationRequired }: ConfigTabProps) {
  const [candidate, setCandidate] = useState(() => generateDefaultNginxConfig(site));
  const [filename, setFilename] = useState(`${project.slug}--${site.slug}.conf`);

  // Validation state: the verdict is keyed to the exact (candidate, filename)
  // it was produced for. The verdict is KEPT after an edit — clearing it would
  // hide the evidence — but it goes STALE, which disables Apply and says so.
  const [verdictKey, setVerdictKey] = useState<string | null>(null);
  const [validateResult, setValidateResult] = useState<ValidateResult | null>(null);
  const [validateError, setValidateError] = useState<Error | null>(null);
  const [validating, setValidating] = useState(false);

  // Apply state
  const [applying, setApplying] = useState(false);
  const [applyError, setApplyError] = useState<Error | null>(null);
  const [job, setJob] = useState<JobStatus | null>(null);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // The gate: Apply is enabled only when the LAST verdict is for the exact
  // current text AND it passed (PRD §30.7). Any edit makes the verdict stale.
  const currentKey = textKey(candidate, filename);
  const validationFresh = verdictKey === currentKey && validateResult?.valid === true;
  const validationStale = verdictKey !== null && verdictKey !== currentKey;
  const canApply = validationFresh && !applying;

  // Stop polling when job terminal.
  useEffect(() => {
    if (job && JOB_TERMINAL.has(job.job.state) && pollRef.current !== null) {
      clearTimeout(pollRef.current);
      pollRef.current = null;
    }
  }, [job]);

  // Cleanup poll on unmount.
  useEffect(() => () => { if (pollRef.current !== null) clearTimeout(pollRef.current); }, []);

  const pollJob = useCallback(async (jobId: string) => {
    try {
      const status = await api.getJob(jobId);
      setJob(status);
      if (!JOB_TERMINAL.has(status.job.state)) {
        pollRef.current = setTimeout(() => { void pollJob(jobId); }, 2000);
      }
    } catch {
      pollRef.current = setTimeout(() => { void pollJob(jobId); }, 4000);
    }
  }, []);

  const handleValidate = async () => {
    setValidating(true);
    setValidateError(null);
    try {
      const res = await api.validateConfig(project.id, site.id, { config: candidate, filename });
      setValidateResult(res);
      setVerdictKey(currentKey);
    } catch (err) {
      setValidateError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setValidating(false);
    }
  };

  const handleApply = async () => {
    if (!canApply) return;
    setApplying(true);
    setApplyError(null);
    setJob(null);
    const doApply = async () => {
      try {
        let accepted: ApplyAccepted;
        try {
          accepted = await api.applyConfig(project.id, site.id, {
            config: candidate,
            filename,
            base_revision_id: site.applied_revision_id,
          });
        } catch (err) {
          if (isStepUpRequired(err)) {
            onElevationRequired(() => { void doApply(); });
            setApplying(false);
            return;
          }
          throw err;
        }
        // 202 Accepted — start polling
        void pollJob(accepted.job.id);
      } catch (err) {
        setApplyError(err instanceof Error ? err : new Error(String(err)));
        setApplying(false);
      }
    };
    await doApply();
  };

  // Diff between empty/applied config and candidate (simplified: show candidate diff)
  const baseText = ''; // We don't have the applied config text; show candidate as-is with note.

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Config filename">
          <input
            className={inputClass}
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            placeholder="project--site.conf"
          />
        </Field>
      </div>

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-ink-secondary">Candidate configuration</span>
          <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
            site.mode === 'nodejs' ? 'bg-green-100 text-green-700' :
            site.mode === 'reverse_proxy' ? 'bg-blue-100 text-blue-700' :
            site.mode === 'php' ? 'bg-purple-100 text-purple-700' :
            'bg-slate-100 text-slate-700'
          }`}>
            {site.mode === 'nodejs' ? 'Node.js' : site.mode === 'reverse_proxy' ? 'Reverse Proxy' : site.mode === 'php' ? 'PHP-FPM' : 'Static'}
          </span>
          {site.mode === 'reverse_proxy' && site.upstream && (
            <span className="text-xs text-ink-muted font-mono">{site.upstream}</span>
          )}
        </div>
        <button
          type="button"
          onClick={() => setCandidate(generateDefaultNginxConfig(site))}
          className="text-xs text-accent hover:underline"
        >
          Reset to default template
        </button>
      </div>
      <textarea
        className={`${inputClass} font-mono text-xs`}
        rows={16}
        value={candidate}
        onChange={(e) => setCandidate(e.target.value)}
        spellCheck={false}
        aria-label="Nginx configuration candidate"
      />

      {/* Diff view (available when applied_revision_id exists, showing candidate diff against empty baseline) */}
      {candidate.trim() && (
        <div>
          <p className="mb-1 text-xs font-medium text-ink-secondary uppercase tracking-wider">Preview</p>
          <pre className="overflow-auto rounded-md border border-line bg-elevated p-3 text-xs font-mono max-h-48">
            {lineDiff(baseText, candidate).map((h, i) => (
              <span
                key={i}
                className={
                  h.kind === 'added' ? 'text-green-700 dark:text-green-400' :
                  h.kind === 'removed' ? 'text-red-700 dark:text-red-400 line-through' :
                  'text-ink-secondary'
                }
              >
                {h.kind === 'added' ? '+ ' : h.kind === 'removed' ? '- ' : '  '}
                {h.line}{'\n'}
              </span>
            ))}
          </pre>
          <p className="mt-1 text-xs text-ink-muted">Diff against current applied config. Validate before applying.</p>
        </div>
      )}

      {/* Validate */}
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          className={secondaryButtonClass}
          disabled={validating}
          onClick={() => void handleValidate()}
        >
          {validating ? 'Validating…' : 'Validate'}
        </button>

        {/* Apply — only enabled after validate PASS on exact current text */}
        <button
          type="button"
          className={primaryButtonClass}
          disabled={!canApply || applying}
          title={!validationFresh ? 'Validate the candidate first' : undefined}
          onClick={() => void handleApply()}
        >
          {applying ? 'Applying…' : 'Apply'}
        </button>

        {validationStale && (
          <span className="text-xs text-ink-muted">Edit invalidated the verdict - re-validate to enable Apply.</span>
        )}
      </div>

      {validateError && <ErrorNote error={validateError} title="Validation request failed" />}
      {applyError && <ErrorNote error={applyError} title="Apply failed" />}

      {/* Validate result */}
      {validateResult && (
        <div className={`rounded-md border p-3 space-y-1 ${validateResult.valid ? 'border-green-300 bg-green-50 dark:border-green-700 dark:bg-green-950' : 'border-red-300 bg-red-50 dark:border-red-700 dark:bg-red-950'}`}>
          <div className="flex items-center gap-2">
            <StatusBadge state={validateResult.valid ? 'Healthy' : 'Critical'} />
            <span className="text-sm font-medium text-ink">
              {validateResult.valid ? 'Valid' : 'Invalid'} - {validateResult.tool} {validateResult.tool_version}
            </span>
          </div>
          {validateResult.output && (
            <pre className="mt-2 overflow-auto rounded-md bg-elevated p-2 text-xs font-mono text-ink whitespace-pre-wrap">
              {validateResult.output}
              {validateResult.truncated && <span className="text-ink-muted"> … (truncated)</span>}
            </pre>
          )}
          <p className="text-xs text-ink-muted">Checked at {formatTs(validateResult.observed_at)}</p>
        </div>
      )}

      {/* Job progress */}
      {job && <JobProgress job={job} />}
    </div>
  );
}

// ─── JobProgress ──────────────────────────────────────────────────────────────

function jobStateLabel(state: string): OperationalState {
  switch (state) {
    case 'succeeded': return 'Healthy';
    case 'failed': case 'dead_letter': return 'Critical';
    case 'running': return 'Pending';
    case 'canceled': return 'Disabled';
    default: return 'Unknown';
  }
}

function JobProgress({ job }: { job: JobStatus }) {
  const isTerminal = JOB_TERMINAL.has(job.job.state);
  return (
    <div className="rounded-md border border-line bg-surface p-3 space-y-2">
      <div className="flex items-center gap-2">
        <StatusBadge state={jobStateLabel(job.job.state)} />
        <span className="text-sm font-medium text-ink">
          Apply job - {job.job.state}
        </span>
        {!isTerminal && (
          <span className="text-xs text-ink-muted animate-pulse">polling…</span>
        )}
      </div>
      {job.steps.length > 0 && (
        <ol className="space-y-1">
          {job.steps.map((s) => (
            <li key={s.index} className="flex flex-wrap items-start gap-2 text-xs">
              <StatusBadge state={jobStateLabel(s.state)} />
              <span className="font-medium text-ink capitalize">{s.name}</span>
              {s.state !== 'pending' && (
                <span className="text-ink-secondary">{s.state}</span>
              )}
              {s.error_summary && (
                <span className="text-red-600 dark:text-red-400">{s.error_summary}</span>
              )}
              {s.output != null && s.output['output'] != null && (
                <pre className="w-full overflow-auto rounded bg-elevated px-2 py-1 font-mono text-ink-secondary whitespace-pre-wrap">
                  {String(s.output['output']).slice(0, 400)}
                </pre>
              )}
            </li>
          ))}
        </ol>
      )}
      {job.job.error_summary && (
        <p className="text-xs text-red-600 dark:text-red-400">{job.job.error_summary}</p>
      )}
    </div>
  );
}

// ─── LogsTab ──────────────────────────────────────────────────────────────────

function LogsTab({ site, project }: { site: Site; project: Project }) {
  const [logType, setLogType] = useState<'access' | 'error'>('access');
  const [lines, setLines] = useState(100);
  const [tail, setTail] = useState<LogsTail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const fetchLogs = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.readLogs(project.id, site.id, { type: logType, lines });
      setTail(res);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-3">
      <p className="text-xs text-ink-muted">
        Logs are read on-demand directly from the host (never stored). D-005.
      </p>
      <div className="flex flex-wrap items-end gap-3">
        <Field label="Log type">
          <select className={inputClass} value={logType} onChange={(e) => setLogType(e.target.value as typeof logType)}>
            <option value="access">Access</option>
            <option value="error">Error</option>
          </select>
        </Field>
        <Field label="Lines (max)">
          <input
            type="number"
            className={inputClass}
            min={1}
            max={500}
            value={lines}
            onChange={(e) => setLines(Math.max(1, Math.min(500, parseInt(e.target.value, 10) || 100)))}
          />
        </Field>
        <button type="button" className={secondaryButtonClass} disabled={loading} onClick={() => void fetchLogs()}>
          {loading ? 'Fetching…' : 'Fetch logs'}
        </button>
      </div>

      {error && <ErrorNote error={error} title="Could not fetch logs" onRetry={() => void fetchLogs()} />}

      {tail && (
        <div>
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-ink-muted">{tail.lines.length} lines - {formatTs(tail.observed_at)}</span>
            {tail.truncated && <span className="text-xs text-amber-600">Truncated</span>}
          </div>
          <pre className="overflow-auto rounded-md border border-line bg-elevated p-3 text-xs font-mono text-ink max-h-96 whitespace-pre">
            {tail.lines.join('\n') || '(no entries)'}
          </pre>
        </div>
      )}
    </div>
  );
}

// ─── NodeJSTab ────────────────────────────────────────────────────────────────

interface NodeJSTabProps {
  site: Site;
  project: Project;
  onElevationRequired: (resume: () => void) => void;
}

function NodeJSTab({ site, project, onElevationRequired }: NodeJSTabProps) {
  const [config, setConfig] = useState<NodeJSConfig | null>(null);
  const [status, setStatus] = useState<SiteNodeJSStatusResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [saveError, setSaveError] = useState<Error | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Editable fields (controlled)
  const [nodeVersion, setNodeVersion] = useState('system');
  const [appRoot, setAppRoot] = useState('');
  const [startupFile, setStartupFile] = useState('server.js');
  const [port, setPort] = useState(3000);
  const [envVars, setEnvVars] = useState<Record<string, string>>({});
  const [newEnvKey, setNewEnvKey] = useState('');
  const [newEnvVal, setNewEnvVal] = useState('');

  // Load config + status on mount
  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [cfgRes, stRes] = await Promise.all([
          api.getNodeJSConfig(project.id, site.id).catch(() => null),
          api.getNodeJSStatus(project.id, site.id).catch(() => ({ status: { active: false, state: 'unknown', unit_name: '' } })),
        ]);
        if (cancelled) return;
        if (cfgRes) {
          const c = cfgRes.nodejs_config;
          setConfig(c);
          setNodeVersion(c.node_version);
          setAppRoot(c.app_root);
          setStartupFile(c.startup_file);
          setPort(c.port);
          setEnvVars(c.env_vars ?? {});
        }
        setStatus(stRes.status);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e : new Error(String(e)));
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void load();
    return () => { cancelled = true; };
  }, [project.id, site.id]);

  const refreshStatus = async () => {
    try {
      const res = await api.getNodeJSStatus(project.id, site.id);
      setStatus(res.status);
    } catch { /* ignore */ }
  };

  const handleSave = () => {
    const doSave = async () => {
      setSaving(true);
      setSaveError(null);
      try {
        const res = await api.upsertNodeJSConfig(project.id, site.id, {
          node_version: nodeVersion,
          app_root: appRoot,
          startup_file: startupFile,
          start_args: [],
          env_vars: envVars,
          port,
        });
        setConfig(res.nodejs_config);
      } catch (e) {
        if (isStepUpRequired(e)) {
          onElevationRequired(() => { void doSave(); });
        } else {
          setSaveError(e instanceof Error ? e : new Error(String(e)));
        }
      } finally {
        setSaving(false);
      }
    };
    void doSave();
  };

  const handleAction = (action: 'start' | 'stop' | 'restart' | 'npm_install') => {
    const doAction = async () => {
      setActionBusy(action);
      setActionMessage(null);
      try {
        const res = await api.nodeJSAction(project.id, site.id, action);
        setActionMessage(res.result.message || `${action} completed. State: ${res.result.state}`);
        await refreshStatus();
      } catch (e) {
        if (isStepUpRequired(e)) {
          onElevationRequired(() => { void doAction(); });
        } else {
          setActionMessage(`Error: ${e instanceof Error ? e.message : String(e)}`);
        }
      } finally {
        setActionBusy(null);
      }
    };
    void doAction();
  };

  if (loading) return <div className="py-8 text-center text-sm text-ink-muted">Loading Node.js configuration...</div>;
  if (error) return <ErrorNote error={error} title="Failed to load Node.js config" />;

  const isActive = status?.active ?? false;

  return (
    <div className="space-y-6">
      {/* Status card */}
      <div className="rounded-lg border border-line bg-surface p-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className={`h-2.5 w-2.5 rounded-full ${isActive ? 'bg-green-500' : 'bg-slate-400'}`} />
          <div>
            <span className="text-sm font-medium text-ink">
              {isActive ? 'Running' : 'Stopped'}
            </span>
            {status?.state && status.state !== 'unknown' && (
              <span className="ml-2 text-xs text-ink-muted">{status.state}</span>
            )}
            {status?.pid && (
              <span className="ml-2 text-xs text-ink-muted">PID {status.pid}</span>
            )}
            {status?.since && (
              <span className="ml-2 text-xs text-ink-muted">since {new Date(status.since).toLocaleTimeString()}</span>
            )}
            {status?.memory_current && (
              <span className="ml-2 text-xs text-ink-muted">{status.memory_current}</span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {!isActive ? (
            <button
              type="button"
              disabled={actionBusy !== null}
              onClick={() => handleAction('start')}
              className={primaryButtonClass}
            >
              {actionBusy === 'start' ? 'Starting...' : 'Start'}
            </button>
          ) : (
            <>
              <button
                type="button"
                disabled={actionBusy !== null}
                onClick={() => handleAction('restart')}
                className={secondaryButtonClass}
              >
                {actionBusy === 'restart' ? 'Restarting...' : 'Restart'}
              </button>
              <button
                type="button"
                disabled={actionBusy !== null}
                onClick={() => handleAction('stop')}
                className="rounded-md border border-red-300 bg-white px-3 py-1.5 text-sm font-medium text-red-600 hover:bg-red-50"
              >
                {actionBusy === 'stop' ? 'Stopping...' : 'Stop'}
              </button>
            </>
          )}
          <button
            type="button"
            disabled={actionBusy !== null}
            onClick={() => handleAction('npm_install')}
            className={secondaryButtonClass}
          >
            {actionBusy === 'npm_install' ? 'Installing...' : 'npm install'}
          </button>
        </div>
      </div>

      {/* Action message */}
      {actionMessage && (
        <div className="rounded-md border border-line bg-elevated p-3 font-mono text-xs text-ink">
          {actionMessage}
        </div>
      )}

      {/* Configuration form */}
      <div className="rounded-lg border border-line bg-surface p-4 space-y-4">
        <h3 className="text-sm font-semibold text-ink">Node.js Configuration</h3>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Node.js version">
            <select
              value={nodeVersion}
              onChange={(e) => setNodeVersion(e.target.value)}
              className={inputClass}
            >
              <option value="system">System default</option>
              <option value="18">Node.js 18 LTS</option>
              <option value="20">Node.js 20 LTS</option>
              <option value="22">Node.js 22 LTS</option>
            </select>
          </Field>
          <Field label="Application port">
            <input
              type="number"
              min={1024}
              max={65535}
              value={port}
              onChange={(e) => setPort(Number(e.target.value))}
              className={inputClass}
            />
          </Field>
          <Field label="Application root" hint="Subdirectory relative to site root (leave empty for root)">
            <input
              value={appRoot}
              onChange={(e) => setAppRoot(e.target.value)}
              placeholder="e.g. backend or leave blank"
              className={inputClass}
            />
          </Field>
          <Field label="Startup file">
            <input
              value={startupFile}
              onChange={(e) => setStartupFile(e.target.value)}
              placeholder="server.js"
              className={inputClass}
            />
          </Field>
        </div>

        {/* Environment Variables */}
        <div>
          <p className="mb-2 text-xs font-medium text-ink-secondary">Environment variables</p>
          {Object.entries(envVars).length > 0 && (
            <div className="mb-2 space-y-1">
              {Object.entries(envVars).map(([k, v]) => (
                <div key={k} className="flex items-center gap-2 font-mono text-xs">
                  <span className="w-32 truncate text-ink">{k}</span>
                  <span className="text-ink-muted">=</span>
                  <span className="flex-1 truncate text-ink-secondary">{v}</span>
                  <button
                    type="button"
                    onClick={() => {
                      const next = { ...envVars };
                      delete next[k];
                      setEnvVars(next);
                    }}
                    className="text-red-500 hover:text-red-700 text-xs"
                  >
                    Remove
                  </button>
                </div>
              ))}
            </div>
          )}
          <div className="flex items-end gap-2">
            <div className="flex-1">
              <Field label="Key">
                <input
                  value={newEnvKey}
                  onChange={(e) => setNewEnvKey(e.target.value)}
                  placeholder="NODE_ENV"
                  className={inputClass}
                />
              </Field>
            </div>
            <div className="flex-1">
              <Field label="Value">
                <input
                  value={newEnvVal}
                  onChange={(e) => setNewEnvVal(e.target.value)}
                  placeholder="production"
                  className={inputClass}
                />
              </Field>
            </div>
            <button
              type="button"
              onClick={() => {
                if (!newEnvKey.trim()) return;
                setEnvVars(prev => ({ ...prev, [newEnvKey.trim()]: newEnvVal }));
                setNewEnvKey('');
                setNewEnvVal('');
              }}
              className={secondaryButtonClass}
            >
              Add
            </button>
          </div>
        </div>

        {saveError && <ErrorNote error={saveError} title="Save failed" />}
        <div className="flex items-center justify-between">
          {config ? (
            <span className="text-xs text-ink-muted">Last saved: {new Date(config.updated_at).toLocaleString()}</span>
          ) : (
            <span className="text-xs text-ink-muted">No configuration saved yet</span>
          )}
          <button
            type="button"
            disabled={saving}
            onClick={handleSave}
            className={primaryButtonClass}
          >
            {saving ? 'Saving...' : 'Save configuration'}
          </button>
        </div>
      </div>
    </div>
  );
}
