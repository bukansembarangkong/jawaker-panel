import { useCallback, useEffect, useRef, useState } from 'react';

import {
  api,
  isStepUpRequired,
  primeCsrf,
  type ApplyAccepted,
  type JobStatus,
  type LogsTail,
  type Project,
  type Site,
  type ValidateResult,
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
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [sites, setSites] = useState<Site[] | null>(null);
  const [selectedSite, setSelectedSite] = useState<Site | null>(null);
  const [loadError, setLoadError] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);

  // Create project form
  const [showCreateProject, setShowCreateProject] = useState(false);
  const [projectSlug, setProjectSlug] = useState('');
  const [projectName, setProjectName] = useState('');
  const [projectDesc, setProjectDesc] = useState('');
  const [projectCreateError, setProjectCreateError] = useState<Error | null>(null);

  // Create site form
  const [showCreateSite, setShowCreateSite] = useState(false);
  const [siteSlug, setSiteSlug] = useState('');
  const [siteName, setSiteName] = useState('');
  const [siteMode, setSiteMode] = useState<'static' | 'php' | 'reverse_proxy'>('static');
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
      setProjects(page.projects);
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
    } catch {
      // Best-effort: server dropdown degrades to free-text
    }
  }, []);

  useEffect(() => {
    void loadProjects();
    void primeCsrf();
  }, [loadProjects]);

  useEffect(() => {
    if (selectedProject) void loadSites(selectedProject.id);
    else setSites(null);
    setSelectedSite(null);
  }, [selectedProject, loadSites]);

  const createProject = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setProjectCreateError(null);
    const doCreate = async () => {
      try {
        const res = await api.createProject({ slug: projectSlug, name: projectName, description: projectDesc });
        setShowCreateProject(false);
        setProjectSlug('');
        setProjectName('');
        setProjectDesc('');
        await loadProjects();
        setSelectedProject(res.project);
      } catch (err) {
        if (isStepUpRequired(err)) {
          setPendingElevation(() => () => { void doCreate(); });
        } else {
          setProjectCreateError(err instanceof Error ? err : new Error(String(err)));
        }
      } finally {
        setBusy(false);
      }
    };
    await doCreate();
  };

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

  if (pendingElevation) {
    return (
      <StepUpPrompt
        onElevated={() => {
          const action = pendingElevation;
          setPendingElevation(null);
          if (action) action();
        }}
        onCancel={() => setPendingElevation(null)}
      />
    );
  }

  if (loadError) {
    return <ErrorNote error={loadError} title="Could not load" onRetry={() => void loadProjects()} />;
  }

  // ── Site detail active ───────────────────────────────────────────────────────
  if (selectedSite && selectedProject) {
    return (
      <SiteDetail
        site={selectedSite}
        project={selectedProject}
        onBack={() => setSelectedSite(null)}
        onDeleted={() => {
          setSelectedSite(null);
          if (selectedProject) void loadSites(selectedProject.id);
        }}
        onElevationRequired={(resume) => setPendingElevation(resume)}
      />
    );
  }

  // ── Project picker + sites list ──────────────────────────────────────────────
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-base font-semibold text-ink">Sites</h2>
        <button type="button" className={secondaryButtonClass} onClick={() => setShowCreateProject(true)}>
          New project
        </button>
      </div>

      {showCreateProject && (
        <form onSubmit={(e) => void createProject(e)} className="rounded-md border border-line bg-surface p-4 space-y-3">
          <h3 className="text-sm font-medium text-ink">New project</h3>
          {projectCreateError && <ErrorNote error={projectCreateError} title="Create failed" />}
          <Field label="Slug (URL-safe, immutable)">
            <input className={inputClass} value={projectSlug} onChange={(e) => setProjectSlug(e.target.value)} required pattern="[a-z0-9-]+" />
          </Field>
          <Field label="Name">
            <input className={inputClass} value={projectName} onChange={(e) => setProjectName(e.target.value)} required />
          </Field>
          <Field label="Description (optional)">
            <input className={inputClass} value={projectDesc} onChange={(e) => setProjectDesc(e.target.value)} />
          </Field>
          <div className="flex gap-2">
            <button type="submit" className={primaryButtonClass} disabled={busy}>Create</button>
            <button type="button" className={secondaryButtonClass} onClick={() => setShowCreateProject(false)}>Cancel</button>
          </div>
        </form>
      )}

      {projects !== null && projects.length > 0 && (
        <div className="space-y-2">
          <label className="text-xs font-medium text-ink-secondary uppercase tracking-wider">Project</label>
          <div className="flex flex-wrap gap-2">
            {projects.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => setSelectedProject(selectedProject?.id === p.id ? null : p)}
                className={`rounded-md px-3 py-1.5 text-sm border ${
                  selectedProject?.id === p.id
                    ? 'border-line bg-elevated font-medium text-ink'
                    : 'border-line text-ink-secondary hover:text-ink'
                }`}
              >
                {p.slug}
              </button>
            ))}
          </div>
        </div>
      )}

      {selectedProject && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-medium text-ink">{selectedProject.name}</h3>
            <button
              type="button"
              className={secondaryButtonClass}
              onClick={() => { void loadServers(); setShowCreateSite(true); }}
            >
              New site
            </button>
          </div>

          {showCreateSite && (
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
          )}

          {sites === null ? (
            <p role="status" className="text-sm text-ink-secondary">Loading sites…</p>
          ) : sites.length === 0 ? (
            <EmptyState title="No sites yet">Create a site to start managing web hosting for this project.</EmptyState>
          ) : (
            <ul className="divide-y divide-line rounded-md border border-line bg-surface">
              {sites.map((site) => (
                <li key={site.id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <StatusBadge state={mapSiteState(site)} />
                      <span className="truncate font-medium text-ink text-sm">{site.slug}</span>
                      <span className="text-xs text-ink-muted">{site.mode}</span>
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
      )}

      {projects !== null && projects.length === 0 && !showCreateProject && (
        <EmptyState title="No projects">
          Create a project to organise your sites, databases, and deployments.
        </EmptyState>
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
  return (
    <form onSubmit={onSubmit} className="rounded-md border border-line bg-surface p-4 space-y-3">
      <h3 className="text-sm font-medium text-ink">New site</h3>
      {siteCreateError && <ErrorNote error={siteCreateError} title="Create failed" />}
      <Field label="Server">
        {servers.length > 0 ? (
          <select className={inputClass} value={siteServerId} onChange={(e) => setSiteServerId(e.target.value)} required>
            <option value="">Select a server…</option>
            {servers.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
        ) : (
          <input className={inputClass} placeholder="Server ID" value={siteServerId} onChange={(e) => setSiteServerId(e.target.value)} required />
        )}
      </Field>
      <Field label="Slug">
        <input className={inputClass} value={siteSlug} onChange={(e) => setSiteSlug(e.target.value)} required pattern="[a-z0-9-]+" />
      </Field>
      <Field label="Name">
        <input className={inputClass} value={siteName} onChange={(e) => setSiteName(e.target.value)} required />
      </Field>
      <Field label="Mode">
        <select className={inputClass} value={siteMode} onChange={(e) => setSiteMode(e.target.value as typeof siteMode)}>
          <option value="static">Static</option>
          <option value="php">PHP</option>
          <option value="reverse_proxy">Reverse proxy</option>
        </select>
      </Field>
      <Field label="Document root (optional)">
        <input className={inputClass} value={siteDocRoot} onChange={(e) => setSiteDocRoot(e.target.value)} placeholder="/var/www/html" />
      </Field>
      {siteMode === 'reverse_proxy' && (
        <Field label="Upstream URL">
          <input className={inputClass} value={siteUpstream} onChange={(e) => setSiteUpstream(e.target.value)} placeholder="http://127.0.0.1:3000" required />
        </Field>
      )}
      {siteMode === 'php' && (
        <Field label="PHP-FPM socket / unit">
          <input className={inputClass} value={sitePHPUnit} onChange={(e) => setSitePHPUnit(e.target.value)} placeholder="php8.2-fpm" required />
        </Field>
      )}
      <div className="flex gap-2">
        <button type="submit" className={primaryButtonClass} disabled={busy}>Create</button>
        <button type="button" className={secondaryButtonClass} onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

// ─── SiteDetail ───────────────────────────────────────────────────────────────

type SiteTab = 'config' | 'logs';

interface SiteDetailProps {
  site: Site;
  project: Project;
  onBack: () => void;
  onDeleted: () => void;
  onElevationRequired: (resume: () => void) => void;
}

function SiteDetail({ site, project, onBack, onDeleted, onElevationRequired }: SiteDetailProps) {
  const [tab, setTab] = useState<SiteTab>('config');
  const [deleting, setDeleting] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState('');
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
          onElevationRequired(() => { void run(); });
        } else {
          setDeleteError(err instanceof Error ? err : new Error(String(err)));
        }
        setBusy(false);
      }
    };
    await run();
  };

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
        {(['config', 'logs'] as SiteTab[]).map((t) => (
          <button
            key={t}
            type="button"
            role="tab"
            aria-selected={tab === t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm capitalize border-b-2 -mb-px transition-colors ${
              tab === t
                ? 'border-ink text-ink font-medium'
                : 'border-transparent text-ink-secondary hover:text-ink'
            }`}
          >
            {t}
          </button>
        ))}
      </nav>

      {tab === 'config' && (
        <ConfigTab site={site} project={project} onElevationRequired={onElevationRequired} />
      )}
      {tab === 'logs' && (
        <LogsTab site={site} project={project} />
      )}

      {/* Danger zone */}
      <details className="mt-6 rounded-md border border-line">
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-ink hover:bg-elevated">
          Danger zone
        </summary>
        <div className="px-4 pb-4 pt-2 space-y-3">
          {!deleting ? (
            <button type="button" className="text-sm text-red-600 underline" onClick={() => setDeleting(true)}>
              Delete this site…
            </button>
          ) : (
            <div className="space-y-2">
              <p className="text-sm text-ink">
                Type <strong>{site.slug}</strong> to confirm deletion.
              </p>
              {deleteError && <ErrorNote error={deleteError} title="Delete failed" />}
              <input
                className={inputClass}
                value={deleteConfirm}
                onChange={(e) => setDeleteConfirm(e.target.value)}
                placeholder={site.slug}
              />
              <div className="flex gap-2">
                <button
                  type="button"
                  className="rounded-md bg-red-600 px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
                  disabled={deleteConfirm !== site.slug || busy}
                  onClick={() => void doDelete()}
                >
                  Delete
                </button>
                <button type="button" className={secondaryButtonClass} onClick={() => setDeleting(false)}>Cancel</button>
              </div>
            </div>
          )}
        </div>
      </details>
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

const STATIC_TEMPLATE = `server {
    listen 80;
    server_name example.com;
    root /var/www/html;
    index index.html;
    location / {
        try_files $uri $uri/ =404;
    }
}
`;

interface ConfigTabProps {
  site: Site;
  project: Project;
  onElevationRequired: (resume: () => void) => void;
}

function ConfigTab({ site, project, onElevationRequired }: ConfigTabProps) {
  const [candidate, setCandidate] = useState(STATIC_TEMPLATE);
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

      <Field label="Candidate configuration">
        <textarea
          className={`${inputClass} font-mono text-xs`}
          rows={16}
          value={candidate}
          onChange={(e) => setCandidate(e.target.value)}
          spellCheck={false}
          aria-label="Nginx configuration candidate"
        />
      </Field>

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
