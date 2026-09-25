/**
 * Minimal API client for the JAWAKER controller.
 *
 * Conventions enforced here (API.md):
 *  - every request may carry a client-generated correlation ID and the
 *    server's X-Request-ID is surfaced on errors for supportability;
 *  - errors are parsed from the canonical envelope, never from raw bodies;
 *  - the CSRF token lives in memory only. It is a non-secret anti-forgery
 *    nonce the server hands out per session, and the server rotates it on
 *    authentication, so persistence would only create a stale-token class of
 *    bug for no benefit.
 *
 * No TanStack Query: there is no shared server cache to coordinate yet, and a
 * second state library for four pages is cost without benefit.
 */

export const REQUEST_ID_HEADER = 'X-Request-ID';
export const CSRF_HEADER = 'X-CSRF-Token';

/** Canonical error envelope (API.md s8). */
export interface ApiErrorEnvelope {
  error: {
    code: string;
    message: string;
    retryable: boolean;
    details?: Record<string, unknown>;
  };
  request_id?: string;
}

/** A parsed API failure with the stable code and correlation ID. */
export class ApiError extends Error {
  readonly code: string;
  readonly retryable: boolean;
  readonly requestId: string | undefined;
  readonly details: Record<string, unknown> | undefined;
  readonly status: number;

  constructor(status: number, envelope: ApiErrorEnvelope | null, fallbackMessage: string) {
    super(envelope?.error.message ?? fallbackMessage);
    this.name = 'ApiError';
    this.status = status;
    this.code = envelope?.error.code ?? 'unknown';
    this.retryable = envelope?.error.retryable ?? false;
    this.requestId = envelope?.request_id;
    this.details = envelope?.error.details;
  }
}

/** True when the failure means "no valid session", rather than a fault. */
export function isUnauthenticated(err: unknown): boolean {
  return err instanceof ApiError && err.status === 401;
}

/**
 * True when the caller could perform this action but must re-authenticate first.
 *
 * The server distinguishes this from a plain refusal with the
 * `step_up_required` code (API.md s8), and the distinction is the whole reason
 * the code exists: a bare 403 must render as "denied", whereas this one must
 * render as a password prompt. Branching on the code rather than the status is
 * what keeps those two paths from collapsing into one.
 */
export function isStepUpRequired(err: unknown): boolean {
  return err instanceof ApiError && err.code === 'step_up_required';
}

function newCorrelationId(): string {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return `req_ui_${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * The double-submit token for this browser session.
 *
 * Held in a module variable rather than localStorage: the value is only
 * meaningful alongside the matching cookie, and writing it to storage would
 * widen its exposure for nothing.
 */
let csrfToken: string | null = null;

/** Prime (or refresh) the CSRF token. Safe to call repeatedly. */
export async function primeCsrf(): Promise<string> {
  const body = await request<{ csrf_token: string }>('/api/v1/auth/csrf');
  csrfToken = body.csrf_token;
  return body.csrf_token;
}

/** Drop the cached token, e.g. after a logout or a rejected request. */
export function clearCsrf(): void {
  csrfToken = null;
}

export interface RequestOptions {
  method?: string;
  body?: unknown;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? 'GET';
  const headers: Record<string, string> = {
    Accept: 'application/json',
    [REQUEST_ID_HEADER]: newCorrelationId(),
  };

  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  // Every mutating request needs the double-submit token. Sending it on GET is
  // harmless but pointless, and the server only checks unsafe methods.
  if (method !== 'GET' && csrfToken) {
    headers[CSRF_HEADER] = csrfToken;
  }

  const response = await fetch(path, {
    method,
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });

  const serverRequestId = response.headers.get(REQUEST_ID_HEADER) ?? undefined;

  if (!response.ok) {
    let envelope: ApiErrorEnvelope | null = null;
    try {
      envelope = (await response.clone().json()) as ApiErrorEnvelope;
    } catch {
      // Non-JSON error body (proxy failure, empty 5xx): keep envelope null.
    }
    if (envelope && !envelope.request_id && serverRequestId) {
      envelope = { ...envelope, request_id: serverRequestId };
    }
    // A rejected CSRF token is never usable again, so stop sending it. The
    // next mutating attempt primes a fresh one instead of retrying with a
    // value the server has already refused.
    if (response.status === 403 && envelope?.error.code === 'forbidden') {
      clearCsrf();
    }
    throw new ApiError(response.status, envelope, `Request failed with status ${response.status}`);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

/** Controller build metadata returned by GET /api/v1/version. */
export interface VersionInfo {
  version: string;
  commit: string;
  build_time: string;
}

/** Health payload returned by GET /healthz. */
export interface HealthInfo {
  status: string;
}

/** The signed-in user, as the server describes them. */
export interface SessionUser {
  id: string;
  email: string;
  display_name: string;
  is_owner?: boolean;
}

/**
 * GET /api/v1/auth/session.
 *
 * Permissions come from the server's own evaluator, so the UI's view of what is
 * allowed cannot drift from what is enforced. The UI is still not the
 * authority: hiding a control is cosmetic and every endpoint re-checks.
 */
export interface AuthSession {
  user: SessionUser;
  session_id: string;
  elevated: boolean;
  permissions: {
    global: string[];
    scoped: string[];
  };
}

/** Login result. The server rotates the CSRF token on authentication. */
export interface LoginResult {
  user: SessionUser;
  session_id: string;
  csrf_token: string;
}

export interface LoginRequest {
  email: string;
  password: string;
  totp_code?: string;
  recovery_code?: string;
}

export interface MFAStatus {
  totp_enrolled: boolean;
  totp_enrollment_pending: boolean;
  recovery_codes_remaining: number;
}

export interface EnrollResult {
  enrollment_id: string;
  otpauth_uri: string;
  secret: string;
  algorithm: string;
  digits: number;
  period_seconds: number;
}

export interface ConfirmResult {
  status: string;
  recovery_codes: string[] | null;
  recovery_codes_error?: string;
}

export interface DisableResult {
  status: string;
  recovery_codes_revoked: number;
  sessions_revoked: number;
}

/**
 * One managed server, as the API describes it.
 *
 * The field names mirror the server's own spelling rather than a preferred
 * local style, so a reader can diff a response against this type without a
 * translation table.
 */
export interface Server {
  id: string;
  name: string;
  description: string;
  address: string;
  /** pending | active | suspended | deleted */
  status: string;
  /** none | active | expiring | expired | revoked */
  cert_status: string;
  os_family: string;
  os_version: string;
  agent_version: string;
  created_at: string;
  last_seen_at?: string;
  enrolled_at?: string;
}

export interface ServerPage {
  servers: Server[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface EnrollmentToken {
  id: string;
  node_name: string;
  expires_at: string;
  created_at: string;
  used_at: string | null;
  revoked_at: string | null;
  /** live | used | expired | revoked — derived server-side from the clock. */
  state: string;
}

/**
 * A freshly minted token. The plaintext exists in this response and nowhere
 * else: it is never stored, and the list endpoint cannot reveal it.
 */
export interface IssuedEnrollmentToken {
  token: string;
  id: string;
  node_name: string;
  expires_at: string;
  controller_fingerprint: string;
  notice: string;
}

export interface ElevateResult {
  elevated: boolean;
  elevated_until: string;
  ttl_seconds: number;
}

export interface ResourceBudget {
  profile: 'tiny' | 'small' | 'medium' | 'large';
  cpus: number;
  total_ram_mb: number;
  worker_concurrency: number;
  job_concurrency: number;
  metrics_interval_seconds: number;
  log_retention_days: number;
  analytics_enabled: boolean;
}

export const api = {
  getVersion: (): Promise<VersionInfo> => request<VersionInfo>('/api/v1/version'),
  getHealth: (): Promise<HealthInfo> => request<HealthInfo>('/healthz'),
  getResourceProfile: (): Promise<{ budget: ResourceBudget; request_id: string }> =>
    request<{ budget: ResourceBudget; request_id: string }>('/api/v1/system/resource-profile'),

  bootstrapStatus: (): Promise<{ requires_bootstrap: boolean }> =>
    request<{ requires_bootstrap: boolean }>('/api/v1/auth/bootstrap'),

  bootstrap: (input: {
    email: string;
    display_name: string;
    password: string;
  }): Promise<{ user_id: string }> =>
    request<{ user_id: string }>('/api/v1/auth/bootstrap', { method: 'POST', body: input }),

  login: async (input: LoginRequest): Promise<LoginResult> => {
    const result = await request<LoginResult>('/api/v1/auth/login', {
      method: 'POST',
      body: input,
    });
    // The server rotated the token as part of authenticating. Adopting the new
    // one here is what keeps the next mutation from being rejected.
    csrfToken = result.csrf_token;
    return result;
  },

  logout: async (): Promise<void> => {
    try {
      await request<{ status: string }>('/api/v1/auth/logout', { method: 'POST' });
    } finally {
      clearCsrf();
    }
  },

  getSession: (): Promise<AuthSession> => request<AuthSession>('/api/v1/auth/session'),

  /**
   * Exchanges a fresh password (and a second factor, when enrolled) for a
   * short-lived elevation window on this session.
   *
   * The window is what the step-up-gated permissions need; without it they
   * refuse every caller. The password is not retained anywhere — it is passed
   * straight through and dropped.
   */
  elevate: (password: string, totpCode?: string): Promise<ElevateResult> =>
    request<ElevateResult>('/api/v1/auth/elevate', {
      method: 'POST',
      body: totpCode ? { password, totp_code: totpCode } : { password },
    }),

  listServers: (): Promise<ServerPage> => request<ServerPage>('/api/v1/servers'),

  getServer: (id: string): Promise<{ server: Server }> =>
    request<{ server: Server }>(`/api/v1/servers/${encodeURIComponent(id)}`),

  deleteServer: (id: string): Promise<{ status: string }> =>
    request<{ status: string }>(`/api/v1/servers/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  listEnrollmentTokens: (): Promise<{ tokens: EnrollmentToken[] }> =>
    request<{ tokens: EnrollmentToken[] }>('/api/v1/servers/enrollment-tokens'),

  createEnrollmentToken: (nodeName: string): Promise<IssuedEnrollmentToken> =>
    request<IssuedEnrollmentToken>('/api/v1/servers/enrollment-tokens', {
      method: 'POST',
      body: { node_name: nodeName },
    }),

  revokeEnrollmentToken: (id: string): Promise<{ status: string }> =>
    request<{ status: string }>(`/api/v1/servers/enrollment-tokens/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  mfaStatus: (): Promise<MFAStatus> => request<MFAStatus>('/api/v1/auth/mfa'),

  mfaEnroll: (password: string): Promise<EnrollResult> =>
    request<EnrollResult>('/api/v1/auth/mfa/totp/enroll', {
      method: 'POST',
      body: { password },
    }),

  mfaConfirm: (code: string): Promise<ConfirmResult> =>
    request<ConfirmResult>('/api/v1/auth/mfa/totp/confirm', {
      method: 'POST',
      body: { code },
    }),

  mfaDisable: (password: string, reason: string): Promise<DisableResult> =>
    request<DisableResult>('/api/v1/auth/mfa/totp/disable', {
      method: 'POST',
      body: { password, reason },
    }),

  mfaRegenerateRecoveryCodes: (password: string, code?: string): Promise<{ recovery_codes: string[] }> =>
    request<{ recovery_codes: string[] }>('/api/v1/auth/mfa/recovery-codes', {
      method: 'POST',
      body: code ? { password, code } : { password },
    }),

  // --- Projects ----------------------------------------------------------------

  listProjects: (params?: { state?: string; limit?: number; offset?: number }): Promise<ProjectPage> => {
    const q = new URLSearchParams();
    if (params?.state) q.set('state', params.state);
    if (params?.limit !== undefined) q.set('limit', String(params.limit));
    if (params?.offset !== undefined) q.set('offset', String(params.offset));
    const qs = q.toString();
    return request<ProjectPage>(`/api/v1/projects${qs ? '?' + qs : ''}`);
  },

  createProject: (input: { slug: string; name: string; description?: string }): Promise<{ project: Project }> =>
    request<{ project: Project }>('/api/v1/projects', { method: 'POST', body: input }),

  getProject: (id: string): Promise<{ project: Project }> =>
    request<{ project: Project }>(`/api/v1/projects/${encodeURIComponent(id)}`),

  // --- Sites -------------------------------------------------------------------

  listSites: (projectId: string, params?: { state?: string; limit?: number; offset?: number }): Promise<SitePage> => {
    const q = new URLSearchParams();
    if (params?.state) q.set('state', params.state);
    if (params?.limit !== undefined) q.set('limit', String(params.limit));
    if (params?.offset !== undefined) q.set('offset', String(params.offset));
    const qs = q.toString();
    return request<SitePage>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/sites${qs ? '?' + qs : ''}`,
    );
  },

  createSite: (
    projectId: string,
    input: { server_id: string; slug: string; name: string; mode: string; doc_root?: string; upstream?: string; php_unit?: string },
  ): Promise<{ site: Site }> =>
    request<{ site: Site }>(`/api/v1/projects/${encodeURIComponent(projectId)}/sites`, {
      method: 'POST',
      body: input,
    }),

  getSite: (projectId: string, id: string): Promise<{ site: Site }> =>
    request<{ site: Site }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/sites/${encodeURIComponent(id)}`,
    ),

  deleteSite: (projectId: string, id: string): Promise<{ status: string }> =>
    request<{ status: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/sites/${encodeURIComponent(id)}`,
      { method: 'DELETE' },
    ),

  validateConfig: (
    projectId: string,
    siteId: string,
    input: { config: string; filename: string },
  ): Promise<ValidateResult> =>
    request<ValidateResult>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/sites/${encodeURIComponent(siteId)}/validate`,
      { method: 'POST', body: input },
    ),

  applyConfig: (
    projectId: string,
    siteId: string,
    input: { config: string; filename: string; base_revision_id?: string },
  ): Promise<ApplyAccepted> =>
    request<ApplyAccepted>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/sites/${encodeURIComponent(siteId)}/apply`,
      { method: 'POST', body: input },
    ),

  readLogs: (
    projectId: string,
    siteId: string,
    params: { type: 'access' | 'error'; lines?: number },
  ): Promise<LogsTail> => {
    const q = new URLSearchParams({ type: params.type });
    if (params.lines !== undefined) q.set('lines', String(params.lines));
    return request<LogsTail>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/sites/${encodeURIComponent(siteId)}/logs?${q.toString()}`,
    );
  },

  // --- Jobs --------------------------------------------------------------------

  getJob: (id: string): Promise<JobStatus> =>
    request<JobStatus>(`/api/v1/jobs/${encodeURIComponent(id)}`),

  // --- Apps -------------------------------------------------------------------

  listApps: (projectId: string, params?: { limit?: number; offset?: number }): Promise<AppPage> => {
    const q = new URLSearchParams();
    if (params?.limit !== undefined) q.set('limit', String(params.limit));
    if (params?.offset !== undefined) q.set('offset', String(params.offset));
    const qs = q.toString();
    return request<AppPage>(`/api/v1/projects/${encodeURIComponent(projectId)}/apps${qs ? '?' + qs : ''}`);
  },

  createApp: (
    projectId: string,
    input: {
      server_id: string;
      slug: string;
      name: string;
      runtime_type: string;
      git_repo_url: string;
      git_ref_default?: string;
      build_program?: string;
      build_args?: string[];
      start_program?: string;
      start_args?: string[];
      working_dir?: string;
      port?: number;
      health_path?: string;
      env_name?: string;
    },
  ): Promise<{ app: App }> =>
    request<{ app: App }>(`/api/v1/projects/${encodeURIComponent(projectId)}/apps`, {
      method: 'POST',
      body: input,
    }),

  getApp: (projectId: string, id: string): Promise<{ app: App }> =>
    request<{ app: App }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(id)}`,
    ),

  deleteApp: (projectId: string, id: string): Promise<{ status: string; delete_after?: string }> =>
    request<{ status: string; delete_after?: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(id)}`,
      { method: 'DELETE' },
    ),

  listEnvVars: (projectId: string, appId: string): Promise<{ env_vars: EnvVar[] }> =>
    request<{ env_vars: EnvVar[] }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(appId)}/env`,
    ),

  setEnvVar: (
    projectId: string,
    appId: string,
    input: { name: string; value_source: 'literal' | 'secret_ref'; value: string },
  ): Promise<{ env_var: EnvVar }> =>
    request<{ env_var: EnvVar }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(appId)}/env`,
      { method: 'POST', body: input },
    ),

  deleteEnvVar: (projectId: string, appId: string, name: string): Promise<{ deleted: boolean }> =>
    request<{ deleted: boolean }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(appId)}/env/${encodeURIComponent(name)}`,
      { method: 'DELETE' },
    ),

  deployApp: (
    projectId: string,
    appId: string,
    input: { commit_sha: string; git_ref?: string },
  ): Promise<DeployAccepted> =>
    request<DeployAccepted>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(appId)}/deploy`,
      { method: 'POST', body: input },
    ),

  listDeployments: (
    projectId: string,
    appId: string,
    params?: { limit?: number; offset?: number },
  ): Promise<DeploymentPage> => {
    const q = new URLSearchParams();
    if (params?.limit !== undefined) q.set('limit', String(params.limit));
    if (params?.offset !== undefined) q.set('offset', String(params.offset));
    const qs = q.toString();
    return request<DeploymentPage>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(appId)}/deployments${qs ? '?' + qs : ''}`,
    );
  },

  getDeployment: (projectId: string, appId: string, depId: string): Promise<{ deployment: Deployment }> =>
    request<{ deployment: Deployment }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(appId)}/deployments/${encodeURIComponent(depId)}`,
    ),

  redeployApp: (projectId: string, appId: string, depId: string): Promise<DeployAccepted> =>
    request<DeployAccepted>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(appId)}/deployments/${encodeURIComponent(depId)}/redeploy`,
      { method: 'POST' },
    ),

  listReleases: (projectId: string, appId: string): Promise<{ releases: Release[] }> =>
    request<{ releases: Release[] }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(appId)}/releases`,
    ),

  rollbackApp: (projectId: string, appId: string): Promise<DeployAccepted> =>
    request<DeployAccepted>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(appId)}/rollback`,
      { method: 'POST' },
    ),

  listWebhookTokens: (projectId: string, appId: string): Promise<{ webhook_tokens: WebhookToken[] }> =>
    request<{ webhook_tokens: WebhookToken[] }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(appId)}/webhook-tokens`,
    ),

  createWebhookToken: (projectId: string, appId: string): Promise<{ token: string; webhook_token: WebhookToken }> =>
    request<{ token: string; webhook_token: WebhookToken }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(appId)}/webhook-tokens`,
      { method: 'POST' },
    ),

  revokeWebhookToken: (projectId: string, appId: string, tokenId: string): Promise<{ revoked: boolean }> =>
    request<{ revoked: boolean }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(appId)}/webhook-tokens/${encodeURIComponent(tokenId)}`,
      { method: 'DELETE' },
    ),

  // --- Preview Environments (PRD §11.6) ----------------------------------------

  listPreviews: (projectId: string, appId: string): Promise<{ previews: Array<{ id: string; app_id: string; branch: string; pr_number?: number; preview_url: string; status: string; created_at: string }>; total: number }> =>
    request<{ previews: Array<{ id: string; app_id: string; branch: string; pr_number?: number; preview_url: string; status: string; created_at: string }>; total: number }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(appId)}/previews`,
    ),

  createPreview: (projectId: string, appId: string, input: { branch: string; pr_number?: number }): Promise<{ preview: { id: string; app_id: string; branch: string; pr_number?: number; preview_url: string; status: string; created_at: string } }> =>
    request<{ preview: { id: string; app_id: string; branch: string; pr_number?: number; preview_url: string; status: string; created_at: string } }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(appId)}/previews`,
      { method: 'POST', body: input },
    ),

  deletePreview: (projectId: string, appId: string, previewId: string): Promise<{ preview_id: string; status: string; message: string }> =>
    request<{ preview_id: string; status: string; message: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(appId)}/previews/${encodeURIComponent(previewId)}`,
      { method: 'DELETE' },
    ),

  // --- Databases (Phase 5) ----------------------------------------------------

  listDatabases: (projectId: string): Promise<DatabasePage> =>
    request<DatabasePage>(`/api/v1/projects/${encodeURIComponent(projectId)}/databases`),

  createDatabase: (
    projectId: string,
    input: {
      server_id: string;
      slug: string;
      name: string;
      engine: string;
      engine_version: string;
      db_name: string;
    },
  ): Promise<{ database: ManagedDatabase }> =>
    request<{ database: ManagedDatabase }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/databases`,
      { method: 'POST', body: input },
    ),

  getDatabase: (projectId: string, id: string): Promise<{ database: ManagedDatabase }> =>
    request<{ database: ManagedDatabase }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(id)}`,
    ),

  updateDatabase: (
    projectId: string,
    id: string,
    input: { name?: string; engine_version?: string },
  ): Promise<{ database: ManagedDatabase }> =>
    request<{ database: ManagedDatabase }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(id)}`,
      { method: 'PATCH', body: input },
    ),

  deleteDatabase: (
    projectId: string,
    id: string,
  ): Promise<{ status: string; database_id: string; delete_after?: string }> =>
    request<{ status: string; database_id: string; delete_after?: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(id)}`,
      { method: 'DELETE' },
    ),

  getConnectionString: (
    projectId: string,
    id: string,
    user?: string,
  ): Promise<{ connection_string: string; username: string; engine: string; db_name: string }> => {
    const q = user ? `?user=${encodeURIComponent(user)}` : '';
    return request<{ connection_string: string; username: string; engine: string; db_name: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(id)}/connection-string${q}`,
    );
  },

  listDatabaseUsers: (projectId: string, id: string): Promise<{ users: DatabaseUser[] }> =>
    request<{ users: DatabaseUser[] }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(id)}/users`,
    ),

  createDatabaseUser: (
    projectId: string,
    id: string,
    input: { username: string; privileges?: string[] },
  ): Promise<{ user: DatabaseUser }> =>
    request<{ user: DatabaseUser }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(id)}/users`,
      { method: 'POST', body: input },
    ),

  revokeDatabaseUser: (
    projectId: string,
    id: string,
    username: string,
  ): Promise<{ revoked: boolean; username: string }> =>
    request<{ revoked: boolean; username: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(id)}/users/${encodeURIComponent(username)}`,
      { method: 'DELETE' },
    ),

  rotateDatabaseUserPassword: (
    projectId: string,
    id: string,
    username: string,
  ): Promise<void> =>
    request<void>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(id)}/users/${encodeURIComponent(username)}/rotate-password`,
      { method: 'POST' },
    ),

  getDatabaseMetrics: (
    projectId: string,
    id: string,
  ): Promise<{ metrics: DatabaseMetrics }> =>
    request<{ metrics: DatabaseMetrics }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(id)}/metrics`,
    ),

  dumpDatabase: (
    projectId: string,
    id: string,
  ): Promise<{ backup_id: string; job_id: string; status: string }> =>
    request<{ backup_id: string; job_id: string; status: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(id)}/dump`,
      { method: 'POST' },
    ),

  restoreDatabase: (
    projectId: string,
    id: string,
    dumpPath: string,
  ): Promise<{ job_id: string; database_id: string; status: string }> =>
    request<{ job_id: string; database_id: string; status: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(id)}/restore`,
      { method: 'POST', body: { dump_path: dumpPath } },
    ),

  // --- Database Rescue Mode (PRD §12.5) ----------------------------------------

  getRescueDiagnostics: (
    projectId: string,
    id: string,
  ): Promise<{ database_id: string; database_state: string; engine: string; failed_jobs: any[]; rescue_actions: string[]; data_dir_protected: boolean; request_id: string }> =>
    request<{ database_id: string; database_state: string; engine: string; failed_jobs: any[]; rescue_actions: string[]; data_dir_protected: boolean; request_id: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(id)}/rescue/diagnostics`,
    ),

  rescueRollback: (
    projectId: string,
    id: string,
  ): Promise<{ database_id: string; state: string; message: string; data_protected: boolean; request_id: string }> =>
    request<{ database_id: string; state: string; message: string; data_protected: boolean; request_id: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(id)}/rescue/rollback`,
      { method: 'POST' },
    ),

  // --- Backups (Phase 6) -------------------------------------------------------

  listBackupPlans: (projectId: string): Promise<BackupPlanPage> =>
    request<BackupPlanPage>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/backup-plans`,
    ),

  createBackupPlan: (
    projectId: string,
    input: CreateBackupPlanInput,
  ): Promise<{ plan: BackupPlan }> =>
    request<{ plan: BackupPlan }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/backup-plans`,
      { method: 'POST', body: input },
    ),

  updateBackupPlan: (
    projectId: string,
    id: string,
    input: UpdateBackupPlanInput,
  ): Promise<{ plan: BackupPlan }> =>
    request<{ plan: BackupPlan }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/backup-plans/${encodeURIComponent(id)}`,
      { method: 'PATCH', body: input },
    ),

  deleteBackupPlan: (
    projectId: string,
    id: string,
  ): Promise<{ status: string; plan_id: string }> =>
    request<{ status: string; plan_id: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/backup-plans/${encodeURIComponent(id)}`,
      { method: 'DELETE' },
    ),

  triggerBackupRun: (
    projectId: string,
    planId: string,
  ): Promise<{ run_id: string; job_id: string; status: string }> =>
    request<{ run_id: string; job_id: string; status: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/backup-plans/${encodeURIComponent(planId)}/run`,
      { method: 'POST' },
    ),

  listBackupRuns: (
    projectId: string,
    planId?: string,
  ): Promise<BackupRunPage> =>
    request<BackupRunPage>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/backup-runs${planId ? `?plan_id=${encodeURIComponent(planId)}` : ''}`,
    ),

  verifyBackupRun: (
    projectId: string,
    runId: string,
  ): Promise<{ run_id: string; job_id: string; status: string }> =>
    request<{ run_id: string; job_id: string; status: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/backup-runs/${encodeURIComponent(runId)}/verify`,
      { method: 'POST' },
    ),

  restoreBackupRun: (
    projectId: string,
    runId: string,
  ): Promise<{ run_id: string; job_id: string; status: string }> =>
    request<{ run_id: string; job_id: string; status: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/backup-runs/${encodeURIComponent(runId)}/restore`,
      { method: 'POST' },
    ),

  deleteBackupRun: (
    projectId: string,
    runId: string,
  ): Promise<{ run_id: string; job_id: string; status: string }> =>
    request<{ run_id: string; job_id: string; status: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/backup-runs/${encodeURIComponent(runId)}`,
      { method: 'DELETE' },
    ),

  createBackupLink: (
    projectId: string,
    runId: string,
    ttlSeconds?: number,
  ): Promise<BackupLinkCreated> =>
    request<BackupLinkCreated>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/backup-runs/${encodeURIComponent(runId)}/links`,
      { method: 'POST', body: ttlSeconds ? { ttl_seconds: ttlSeconds } : {} },
    ),
};

// --- Domain types (mirrors API response shapes) --------------------------------

export interface Project {
  id: string;
  slug: string;
  name: string;
  description: string;
  state: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
  delete_after?: string;
  deleted_at?: string;
}

export interface ProjectPage {
  projects: Project[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface Site {
  id: string;
  project_id: string;
  server_id: string;
  slug: string;
  name: string;
  /** static | php | reverse_proxy */
  mode: string;
  /** active | pending_delete | deleted */
  state: string;
  doc_root: string;
  upstream: string;
  php_unit: string;
  applied_revision_id?: string;
  created_at: string;
  updated_at: string;
  delete_after?: string;
  deleted_at?: string;
}

export interface SitePage {
  sites: Site[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface ValidateResult {
  valid: boolean;
  tool: string;
  tool_version: string;
  output: string;
  truncated: boolean;
  staged: string;
  observed_at: string;
  request_id: string;
}

export interface ApplyAccepted {
  revision_id: string;
  job: { id: string; state: string };
  request_id: string;
}

export interface LogsTail {
  site_id: string;
  log_type: string;
  lines: string[];
  truncated: boolean;
  observed_at: string;
  request_id: string;
}

export interface JobStep {
  index: number;
  name: string;
  state: string;
  output: Record<string, unknown> | null;
  error_code: string;
  error_summary: string;
  attempt: number;
  started_at?: string;
  finished_at?: string;
}

export interface JobStatus {
  job: {
    id: string;
    type: string;
    server_id: string;
    project_id: string;
    state: string;
    priority: number;
    attempt_count: number;
    max_attempts: number;
    error_code: string;
    error_summary: string;
    created_at: string;
    started_at?: string;
    finished_at?: string;
  };
  steps: JobStep[];
  request_id: string;
}

export interface App {
  id: string;
  project_id: string;
  server_id: string;
  slug: string;
  name: string;
  /** node | bun | python | php | static */
  runtime_type: string;
  /** active | suspended | pending_delete | deleted */
  state: string;
  git_repo_url: string;
  git_ref_default: string;
  build_program: string;
  build_args: string[];
  start_program: string;
  start_args: string[];
  working_dir: string;
  port: number | null;
  health_path: string | null;
  env_name: string;
  created_at: string;
  updated_at: string;
  delete_after?: string | null;
}

export interface AppPage {
  apps: App[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface EnvVar {
  id: string;
  name: string;
  /** literal | secret_ref */
  value_source: string;
  /** Present only for literal rows. secret_ref values are NEVER returned. */
  value?: string;
  /** Present only for secret_ref rows — the opaque secret:// URI, not a value. */
  secret_ref?: string | null;
  created_at: string;
  updated_at: string;
}

export interface Deployment {
  id: string;
  app_id: string;
  project_id: string;
  server_id: string;
  /** manual | webhook | rollback */
  trigger: string;
  commit_sha: string | null;
  git_ref: string;
  /** queued | running | succeeded | failed | rolled_back | canceled */
  state: string;
  error_code: string;
  error_summary: string;
  job_id: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface DeploymentPage {
  deployments: Deployment[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface DeployAccepted {
  deployment_id: string;
  job: { id: string; state: string };
  request_id: string;
}

export interface Release {
  id: string;
  app_id: string;
  deployment_id: string;
  release_path: string;
  commit_sha: string;
  is_current: boolean;
  /** unknown | healthy | unhealthy */
  health_state: string;
  created_at: string;
}

export interface WebhookToken {
  id: string;
  app_id: string;
  /** active | revoked */
  state: string;
  created_at: string;
  last_used_at: string | null;
}

// --- Databases (Phase 5) ----------------------------------------------------

export interface ManagedDatabase {
  id: string;
  project_id: string;
  server_id: string;
  slug: string;
  name: string;
  /** postgresql | mariadb */
  engine: 'postgresql' | 'mariadb' | string;
  engine_version: string;
  db_name: string;
  /** active | suspended | pending_delete | deleted */
  state: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
  delete_after?: string;
  deleted_at?: string;
}

export interface DatabasePage {
  databases: ManagedDatabase[];
  total: number;
}

export interface DatabaseUser {
  id: string;
  database_id: string;
  username: string;
  secret_ref: string;
  privileges: string[];
  created_at: string;
}

export interface SlowQuery {
  query: string;
  calls: number;
  total_time_ms: number;
  mean_time_ms: number;
}

export interface DatabaseMetrics {
  connections: number;
  active_queries: number;
  slow_queries_last_5m: number;
  top_slow_queries?: SlowQuery[];
  observed_at: string;
}

// --- Backups (Phase 6) ---------------------------------------------------------

export interface BackupPlan {
  id: string;
  project_id: string;
  server_id: string;
  name: string;
  slug: string;
  scope_type: 'project' | 'site' | 'database' | string;
  scope_id?: string;
  destination_type: 'local' | 's3' | string;
  schedule_cron: string;
  next_run_at?: string;
  enabled: boolean;
  retention_count: number;
  retention_days: number;
  state: string;
  created_at: string;
  updated_at: string;
  delete_after?: string;
}

export interface BackupPlanPage {
  plans: BackupPlan[];
  total: number;
}

export interface CreateBackupPlanInput {
  server_id: string;
  name: string;
  slug: string;
  scope_type: string;
  scope_id?: string;
  destination_type: string;
  destination_config?: Record<string, unknown>;
  schedule_cron?: string;
  retention_count?: number;
  retention_days?: number;
}

export interface UpdateBackupPlanInput {
  name?: string;
  schedule_cron?: string;
  enabled?: boolean;
  retention_count?: number;
  retention_days?: number;
}

export interface BackupRun {
  id: string;
  plan_id?: string;
  project_id: string;
  server_id: string;
  trigger: string;
  state: string;
  archive_path: string;
  archive_size: number;
  sha256: string;
  verification: string;
  job_id?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  failed_reason?: string;
}

export interface BackupRunPage {
  runs: BackupRun[];
  total: number;
}

/** Returned once at link creation. The token is never retrievable again. */
export interface BackupLinkCreated {
  token: string;
  link_id: string;
  expires_at: string;
  single_use: boolean;
  request_id: string;
}

// --- Phase 7: Observability ---------------------------------------------------

export interface MetricSample {
  server_id: string;
  metric: string;
  value: number;
  observed_at: string;
}

export interface MetricSamplesPage {
  server_id: string;
  metric: string;
  samples: MetricSample[];
  request_id: string;
}

export interface AlertRule {
  id: string;
  server_id: string;
  name: string;
  metric: string;
  comparator: 'gt' | 'lt';
  threshold: number;
  duration_seconds: number;
  severity: 'info' | 'warning' | 'critical';
  enabled: boolean;
  state: 'active' | 'suspended';
  created_by?: string;
  created_at: string;
  updated_at: string;
}

export interface AlertRulePage {
  rules: AlertRule[];
  total: number;
  request_id: string;
}

export interface CreateAlertRuleInput {
  server_id: string;
  name: string;
  metric: string;
  comparator: 'gt' | 'lt';
  threshold: number;
  duration_seconds: number;
  severity?: 'info' | 'warning' | 'critical';
}

export interface UpdateAlertRuleInput {
  name?: string;
  threshold?: number;
  duration_seconds?: number;
  severity?: string;
  enabled?: boolean;
  state?: string;
}

export interface AlertIncident {
  id: string;
  rule_id: string;
  server_id: string;
  state: 'open' | 'resolved';
  dedup_key: string;
  opened_at: string;
  resolved_at: string | null;
  notified_at: string | null;
}

export interface IncidentPage {
  incidents: AlertIncident[];
  total: number;
  request_id: string;
}

export interface ReportSchedule {
  id: string;
  name: string;
  cadence: 'daily' | 'weekly' | 'monthly';
  next_run_at: string;
  enabled: boolean;
  last_run_at: string | null;
  created_by?: string;
  created_at: string;
}

export interface SchedulePage {
  schedules: ReportSchedule[];
  total: number;
  request_id: string;
}

export interface SLOSummary {
  controller_availability_pct: number;
  node_connectivity_pct: number;
  backup_success_rate_pct: number;
  deployment_success_rate_pct: number;
  job_latency_avg_ms: number;
  error_budget_remaining_pct: number;
  active_incidents: number;
  evaluated_at: string;
}

export interface CreateScheduleInput {
  name: string;
  cadence: 'daily' | 'weekly' | 'monthly';
}

// Observe API methods appended to the api object (see bottom of file).
// They are exported here as standalone functions for tree-shaking friendliness.
export const observeApi = {
  getMetrics(serverId: string, metric: string, since?: string): Promise<MetricSamplesPage> {
    const q = since
      ? `?metric=${encodeURIComponent(metric)}&since=${encodeURIComponent(since)}`
      : `?metric=${encodeURIComponent(metric)}`;
    return request<MetricSamplesPage>(`/api/v1/servers/${encodeURIComponent(serverId)}/metrics${q}`);
  },
  listRules(serverId?: string): Promise<AlertRulePage> {
    const q = serverId ? `?server_id=${encodeURIComponent(serverId)}` : '';
    return request<AlertRulePage>(`/api/v1/alert-rules${q}`);
  },
  createRule(input: CreateAlertRuleInput): Promise<{ rule: AlertRule; request_id: string }> {
    return request<{ rule: AlertRule; request_id: string }>('/api/v1/alert-rules', { method: 'POST', body: input });
  },
  updateRule(id: string, input: UpdateAlertRuleInput): Promise<{ rule: AlertRule; request_id: string }> {
    return request<{ rule: AlertRule; request_id: string }>(`/api/v1/alert-rules/${encodeURIComponent(id)}`, { method: 'PATCH', body: input });
  },
  deleteRule(id: string): Promise<{ status: string; request_id: string }> {
    return request<{ status: string; request_id: string }>(`/api/v1/alert-rules/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  listIncidents(serverId?: string, state?: string): Promise<IncidentPage> {
    const params = new URLSearchParams();
    if (serverId) params.set('server_id', serverId);
    if (state) params.set('state', state);
    const q = params.toString() ? `?${params.toString()}` : '';
    return request<IncidentPage>(`/api/v1/incidents${q}`);
  },
  resolveIncident(id: string): Promise<{ status: string; id: string; request_id: string }> {
    return request<{ status: string; id: string; request_id: string }>(
      `/api/v1/incidents/${encodeURIComponent(id)}/resolve`,
      { method: 'POST', body: {} },
    );
  },
  listSchedules(): Promise<SchedulePage> {
    return request<SchedulePage>('/api/v1/report-schedules');
  },
  createSchedule(input: CreateScheduleInput): Promise<{ schedule: ReportSchedule; request_id: string }> {
    return request<{ schedule: ReportSchedule; request_id: string }>('/api/v1/report-schedules', { method: 'POST', body: input });
  },
  deleteSchedule(id: string): Promise<{ status: string; request_id: string }> {
    return request<{ status: string; request_id: string }>(`/api/v1/report-schedules/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  getSLOSummary(): Promise<{ slo: SLOSummary; request_id: string }> {
    return request<{ slo: SLOSummary; request_id: string }>('/api/v1/slo/summary');
  },
};

export interface DNSProvider {
  id: string;
  project_id: string;
  name: string;
  provider: string;
  state: string;
  created_at: string;
}

export interface DNSZone {
  id: string;
  project_id: string;
  provider_id: string;
  name: string;
  state: string;
  created_at: string;
}

export interface DNSRecord {
  id: string;
  zone_id: string;
  name: string;
  type: string;
  content: string;
  ttl: number;
  state: string;
  created_at: string;
}

export interface Certificate {
  id: string;
  project_id: string;
  issued_at: string;
  not_after: string;
  identifiers: string[];
  issuer: string;
  state: string;
  created_at: string;
}

export interface CertOrder {
  id: string;
  project_id: string;
  state: string;
  identifiers: string[];
  created_at: string;
}

export const dnsTlsApi = {
  listProviders(projectId: string): Promise<{ providers: DNSProvider[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/dns-providers`);
  },
  createProvider(projectId: string, input: { name: string; provider: string; token: string }): Promise<{ provider: DNSProvider; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/dns-providers`, { method: 'POST', body: input });
  },
  deleteProvider(projectId: string, id: string): Promise<{ status: string; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/dns-providers/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  listZones(projectId: string): Promise<{ zones: DNSZone[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/dns-zones`);
  },
  createZone(projectId: string, input: { provider_id: string; name: string }): Promise<{ zone: DNSZone; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/dns-zones`, { method: 'POST', body: input });
  },
  deleteZone(projectId: string, id: string): Promise<{ status: string; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/dns-zones/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  listRecords(projectId: string, zoneId: string): Promise<{ records: DNSRecord[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/dns-zones/${encodeURIComponent(zoneId)}/records`);
  },
  createRecord(projectId: string, zoneId: string, input: { name: string; type: string; content: string; ttl: number }): Promise<{ record: DNSRecord; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/dns-zones/${encodeURIComponent(zoneId)}/records`, { method: 'POST', body: input });
  },
  deleteRecord(projectId: string, zoneId: string, id: string): Promise<{ status: string; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/dns-zones/${encodeURIComponent(zoneId)}/records/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  listCertificates(projectId: string): Promise<{ certificates: Certificate[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/certificates`);
  },
  importCertificate(projectId: string, input: { chain_pem: string; private_key_pem: string }): Promise<{ certificate: Certificate; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/certificates/import`, { method: 'POST', body: input });
  },
  revokeCertificate(projectId: string, id: string, reason: string): Promise<{ certificate: Certificate; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/certificates/${encodeURIComponent(id)}/revoke`, { method: 'POST', body: { reason } });
  },
  listOrders(projectId: string): Promise<{ orders: CertOrder[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/cert-orders`);
  },
  createOrder(projectId: string, input: { identifiers: string[] }): Promise<{ order: CertOrder; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/cert-orders`, { method: 'POST', body: input });
  },
  cancelOrder(projectId: string, id: string): Promise<{ order: CertOrder; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/cert-orders/${encodeURIComponent(id)}/cancel`, { method: 'POST', body: {} });
  },
};

// --- Containers (Phase 9) ---------------------------------------------------

export interface ContainerRegistry {
  id: string;
  project_id: string;
  name: string;
  host: string;
  has_credential: boolean;
  created_at: string;
  deleted_at?: string;
}

export interface ContainerStack {
  id: string;
  project_id: string;
  server_id: string;
  name: string;
  state: string;
  created_at: string;
  deleted_at?: string;
}

export interface Container {
  id: string;
  project_id: string;
  server_id: string;
  stack_id?: string;
  name: string;
  container_id: string;
  image_ref: string;
  state: string;
  cpu_limit: number;
  mem_limit_mb: number;
  privileged: boolean;
  health: string;
  started_at?: string;
  created_at: string;
  deleted_at?: string;
}

export interface ContainerVolume {
  id: string;
  project_id: string;
  server_id: string;
  container_id?: string;
  name: string;
  driver: string;
  mount_point: string;
  size_bytes?: number;
  created_at: string;
  deleted_at?: string;
}

export interface ContainerLogsResult {
  container_id: string;
  name: string;
  lines: string[];
  truncated: boolean;
  observed_at: string;
  request_id: string;
}

export const containerApi = {
  // Registries
  listRegistries(projectId: string): Promise<{ registries: ContainerRegistry[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/container-registries`);
  },
  createRegistry(projectId: string, input: { name: string; host: string; password?: string }): Promise<{ registry: ContainerRegistry; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/container-registries`, { method: 'POST', body: input });
  },
  deleteRegistry(projectId: string, id: string): Promise<{ deleted: boolean; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/container-registries/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },

  // Compose stacks
  listStacks(projectId: string): Promise<{ stacks: ContainerStack[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/container-stacks`);
  },
  createStack(projectId: string, input: { server_id: string; name: string; compose_yaml?: string }): Promise<{ stack: ContainerStack; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/container-stacks`, { method: 'POST', body: input });
  },
  deleteStack(projectId: string, id: string): Promise<{ deleted: boolean; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/container-stacks/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },

  // Containers
  listContainers(projectId: string, serverId?: string): Promise<{ containers: Container[]; total: number; request_id: string }> {
    const q = serverId ? `?server_id=${encodeURIComponent(serverId)}` : '';
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/containers${q}`);
  },
  getContainer(projectId: string, id: string): Promise<{ container: Container; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/containers/${encodeURIComponent(id)}`);
  },
  getContainerLogs(projectId: string, id: string): Promise<ContainerLogsResult> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/containers/${encodeURIComponent(id)}/logs`);
  },
  listPrivilegedContainers(projectId: string): Promise<{ containers: Container[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/containers/privileged`);
  },
  startContainer(projectId: string, id: string): Promise<{ container_id: string; name: string; action: string; success: boolean; message?: string; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/containers/${encodeURIComponent(id)}/start`, { method: 'POST' });
  },
  stopContainer(projectId: string, id: string): Promise<{ container_id: string; name: string; action: string; success: boolean; message?: string; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/containers/${encodeURIComponent(id)}/stop`, { method: 'POST' });
  },
  restartContainer(projectId: string, id: string): Promise<{ container_id: string; name: string; action: string; success: boolean; message?: string; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/containers/${encodeURIComponent(id)}/restart`, { method: 'POST' });
  },

  // Volumes
  listVolumes(projectId: string): Promise<{ volumes: ContainerVolume[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/container-volumes`);
  },
};

// ── Phase 10 — Networking API ─────────────────────────────────────────────────

export interface FirewallRule {
  id: string;
  server_id: string;
  chain: string;
  priority: number;
  protocol: string;
  source_cidr: string;
  dest_cidr: string;
  dest_port_min: number;
  dest_port_max: number;
  action: string;
  enabled: boolean;
  description: string;
  state: string;
  created_at: string;
}

export interface FirewallChain {
  table: string;
  chain: string;
  policy?: string;
  rules: Array<{ num: number; target: string; protocol: string; source: string; destination: string; options?: string }>;
}

export interface PortForward {
  id: string;
  server_id: string;
  protocol: string;
  listen_address: string;
  listen_port: number;
  dest_address: string;
  dest_port: number;
  enabled: boolean;
  description: string;
  state: string;
  created_at: string;
}

export interface NetworkZone {
  id: string;
  server_id: string;
  name: string;
  kind: string;
  interfaces: string;
  created_at: string;
}

export interface ListeningPort {
  protocol: string;
  local_address: string;
  local_port: number;
  pid?: number;
  process_name?: string;
}

export interface WireGuardPeer {
  id: string;
  server_id: string;
  public_key: string;
  label: string;
  allowed_ips: string;
  endpoint: string;
  persistent_keepalive: number;
  enabled: boolean;
  created_at: string;
}

export interface NetDiagResult {
  mode: string;
  target: string;
  output: string;
  success: boolean;
  observed_at: string;
}

export interface NetworkApplyLog {
  id: string;
  server_id: string;
  applied_by: string;
  outcome: string;
  error_message: string;
  created_at: string;
}

export const networkApi = {
  listRules(serverId: string): Promise<{ rules: FirewallRule[]; total: number; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/firewall/rules`);
  },
  createRule(serverId: string, input: { chain: string; priority?: number; protocol?: string; source_cidr?: string; dest_cidr?: string; dest_port_min?: number; dest_port_max?: number; action?: string; enabled?: boolean; description?: string }): Promise<{ rule: FirewallRule; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/firewall/rules`, { method: 'POST', body: input });
  },
  deleteRule(serverId: string, id: string): Promise<void> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/firewall/rules/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  applyFirewall(serverId: string): Promise<{ log: NetworkApplyLog; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/firewall/apply`, { method: 'POST', body: {} });
  },
  getLiveFirewall(serverId: string, table?: string): Promise<{ chains: FirewallChain[]; observed_at: string; request_id: string }> {
    const q = table ? `?table=${encodeURIComponent(table)}` : '';
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/firewall/live${q}`);
  },
  listForwards(serverId: string): Promise<{ forwards: PortForward[]; total: number; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/port-forwards`);
  },
  createForward(serverId: string, input: { protocol: string; listen_address?: string; listen_port: number; dest_address: string; dest_port: number; enabled?: boolean; description?: string }): Promise<{ forward: PortForward; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/port-forwards`, { method: 'POST', body: input });
  },
  deleteForward(serverId: string, id: string): Promise<void> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/port-forwards/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  listZones(serverId: string): Promise<{ zones: NetworkZone[]; total: number; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/network/zones`);
  },
  createZone(serverId: string, input: { name: string; kind?: string; interfaces?: string }): Promise<{ zone: NetworkZone; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/network/zones`, { method: 'POST', body: input });
  },
  deleteZone(serverId: string, id: string): Promise<void> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/network/zones/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  getPortInventory(serverId: string, protocol?: string): Promise<{ ports: ListeningPort[]; total: number; observed_at: string; request_id: string }> {
    const q = protocol ? `?protocol=${encodeURIComponent(protocol)}` : '';
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/network/ports${q}`);
  },
  listPeers(serverId: string): Promise<{ peers: WireGuardPeer[]; total: number; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/wireguard/peers`);
  },
  createPeer(serverId: string, input: { public_key: string; label?: string; allowed_ips?: string; endpoint?: string; persistent_keepalive?: number; enabled?: boolean }): Promise<{ peer: WireGuardPeer; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/wireguard/peers`, { method: 'POST', body: input });
  },
  deletePeer(serverId: string, id: string): Promise<void> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/wireguard/peers/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  runDiag(serverId: string, input: { target: string; mode: 'ping' | 'trace' }): Promise<{ result: NetDiagResult; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/network/diag`, { method: 'POST', body: input });
  },
  listApplyLog(serverId: string): Promise<{ logs: NetworkApplyLog[]; total: number; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/network/apply-log`);
  },
};

// ─── Phase 11 — Security Center API ───────────────────────────────────────────

export interface HardeningCheck {
  id: string;
  server_id: string;
  check_name: string;
  category: string;
  severity: string;
  status: string;
  title: string;
  description: string;
  remediation: string;
  observed_at: string;
  created_at: string;
}

export interface HardeningFinding {
  check_name: string;
  category: string;
  severity: string;
  status: string;
  title: string;
  description: string;
  remediation: string;
}

export interface SSHPosture {
  permit_root_login: string;
  password_auth: string;
  pubkey_auth: string;
  port: number;
  protocol_versions: string;
  active_sessions: number;
  auth_failures_1h: number;
  observed_at: string;
}

export interface SecurityEvent {
  id: string;
  server_id: string;
  source: string;
  kind: string;
  remote_ip: string;
  country: string;
  service: string;
  raw_line: string;
  observed_at: string;
}

export interface BanEntry {
  id: string;
  server_id: string;
  ip: string;
  source: string;
  reason: string;
  expires_at?: string;
  banned_at: string;
  unbanned_at?: string;
  state: string;
  created_at: string;
}

export interface LiveBan {
  ip: string;
  source: string;
  jail?: string;
  banned_at?: string;
  expires_at?: string;
}

export interface WAFRule {
  id: string;
  server_id: string;
  kind: string;
  pattern: string;
  action: string;
  enabled: boolean;
  priority: number;
  description: string;
  created_at: string;
}

export const securityCenterApi = {
  // Hardening
  listChecks(serverId: string): Promise<{ checks: HardeningCheck[]; total: number; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/security/hardening`);
  },
  triggerScan(serverId: string, categories?: string[]): Promise<{ findings: HardeningFinding[]; total: number; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/security/hardening/scan`, { method: 'POST', body: { categories } });
  },

  // SSH posture
  getSSHPosture(serverId: string): Promise<{ posture: SSHPosture; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/security/ssh-posture`);
  },

  // Events
  listEvents(serverId: string): Promise<{ events: SecurityEvent[]; total: number; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/security/events`);
  },

  // Bans
  listBans(serverId: string): Promise<{ bans: BanEntry[]; total: number; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/security/bans`);
  },
  createBan(serverId: string, input: { ip: string; reason?: string; source?: string }): Promise<{ ban: BanEntry; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/security/bans`, { method: 'POST', body: input });
  },
  removeBan(serverId: string, id: string): Promise<{ deleted: boolean; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/security/bans/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  getLiveBans(serverId: string, source?: string): Promise<{ bans: LiveBan[]; total: number; observed_at: string; request_id: string }> {
    const q = source ? `?source=${encodeURIComponent(source)}` : '';
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/security/bans/live${q}`);
  },

  // WAF rules
  listWAFRules(serverId: string): Promise<{ rules: WAFRule[]; total: number; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/security/waf-rules`);
  },
  createWAFRule(serverId: string, input: { kind?: string; pattern: string; action?: string; enabled?: boolean; priority?: number; description?: string }): Promise<{ rule: WAFRule; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/security/waf-rules`, { method: 'POST', body: input });
  },
  deleteWAFRule(serverId: string, id: string): Promise<{ deleted: boolean; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/security/waf-rules/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
};

// ── Phase 12: Update platform ──────────────────────────────────────────────────

export interface UpdateRelease {
  id: string;
  channel: string;
  version: string;
  tag: string;
  notes: string;
  artifact_url: string;
  checksum_url: string;
  signature_url: string;
  published_at: string;
  discovered_at: string;
  compatible: boolean | null;
}

export interface UpdateJob {
  id: string;
  release_id: string;
  snapshot_id: string | null;
  state: string;
  triggered_by: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string;
  created_at: string;
}

export interface UpdateSnapshot {
  id: string;
  release_id: string;
  state: string;
  manifest: Record<string, unknown>;
  snapshot_at: string | null;
  notes: string;
  created_at: string;
}

export interface CanaryEntry {
  id: string;
  job_id: string;
  server_id: string;
  state: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string;
}

export interface ModuleUpdate {
  id: string;
  module_name: string;
  current_ver: string;
  latest_ver: string | null;
  state: string;
  last_checked: string | null;
  updated_at: string | null;
  created_at: string;
}

export const updatesApi = {
  // Releases
  listReleases(channel?: string): Promise<{ releases: UpdateRelease[]; total: number; request_id: string }> {
    const q = channel ? `?channel=${encodeURIComponent(channel)}` : '';
    return request(`/api/v1/updates/releases${q}`);
  },
  syncRelease(input: Omit<UpdateRelease, 'id' | 'discovered_at' | 'compatible'>): Promise<{ release: UpdateRelease; request_id: string }> {
    return request('/api/v1/updates/releases/sync', { method: 'POST', body: input });
  },

  // Preflight
  runPreflight(releaseId: string): Promise<{ release_id: string; compatible: boolean; request_id: string }> {
    return request(`/api/v1/updates/releases/${encodeURIComponent(releaseId)}/preflight`, { method: 'POST', body: {} });
  },

  // Jobs
  listJobs(): Promise<{ jobs: UpdateJob[]; total: number; request_id: string }> {
    return request('/api/v1/updates/jobs');
  },
  getJob(id: string): Promise<{ job: UpdateJob; request_id: string }> {
    return request(`/api/v1/updates/jobs/${encodeURIComponent(id)}`);
  },
  applyUpdate(releaseId: string): Promise<{ job: UpdateJob; request_id: string }> {
    return request('/api/v1/updates/apply', { method: 'POST', body: { release_id: releaseId } });
  },

  // Snapshots
  getSnapshot(id: string): Promise<{ snapshot: UpdateSnapshot; request_id: string }> {
    return request(`/api/v1/updates/snapshots/${encodeURIComponent(id)}`);
  },

  // Canary
  listCanary(jobId: string): Promise<{ entries: CanaryEntry[]; total: number; request_id: string }> {
    return request(`/api/v1/updates/jobs/${encodeURIComponent(jobId)}/canary`);
  },
  applyCanary(jobId: string, serverId: string, expectedSha256: string): Promise<{ result: unknown; request_id: string }> {
    return request(`/api/v1/updates/jobs/${encodeURIComponent(jobId)}/canary/${encodeURIComponent(serverId)}/apply`, {
      method: 'POST',
      body: { expected_sha256: expectedSha256 },
    });
  },
  fleetRollout(releaseId: string, batchSize = 1): Promise<{ job_id: string; release_id: string; total_nodes: number; batch_size: number; status: string; request_id: string }> {
    return request('/api/v1/updates/fleet/rollout', {
      method: 'POST',
      body: { release_id: releaseId, batch_size: batchSize },
    });
  },

  // Modules
  listModules(): Promise<{ modules: ModuleUpdate[]; total: number; request_id: string }> {
    return request('/api/v1/updates/modules');
  },
};

// ── Mail platform (Phase 13) ───────────────────────────────────────────────────

export interface MailDomain {
  id: string;
  project_id: string;
  server_id: string;
  domain: string;
  state: string;
  spf_ok: boolean;
  dkim_ok: boolean;
  dmarc_ok: boolean;
  created_at: string;
  updated_at: string;
}

export interface MailMailbox {
  id: string;
  domain_id: string;
  local_part: string;
  state: string;
  quota_mb: number;
}

export interface MailAlias {
  id: string;
  domain_id: string;
  local_part: string;
  destination: string;
  created_at: string;
}

export interface MailQueueEntry {
  id: string;
  domain_id: string;
  sender: string;
  recipients: string;
  status: string;
  queued_at: string | null;
  delivered_at: string | null;
  error_message: string;
}

export const mailApi = {
  listDomains(projectId: string): Promise<{ domains: MailDomain[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/mail/domains`);
  },
  createDomain(projectId: string, serverId: string, domain: string): Promise<{ domain: MailDomain; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/mail/domains`, {
      method: 'POST',
      body: { server_id: serverId, domain },
    });
  },
  getDomain(projectId: string, id: string): Promise<{ domain: MailDomain; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/mail/domains/${encodeURIComponent(id)}`);
  },
  deleteDomain(projectId: string, id: string): Promise<{ deleted: boolean; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/mail/domains/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },

  listMailboxes(projectId: string, domainId: string): Promise<{ mailboxes: MailMailbox[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/mail/domains/${encodeURIComponent(domainId)}/mailboxes`);
  },
  deleteMailbox(projectId: string, domainId: string, id: string): Promise<{ deleted: boolean; request_id: string }> {
    return request(
      `/api/v1/projects/${encodeURIComponent(projectId)}/mail/domains/${encodeURIComponent(domainId)}/mailboxes/${encodeURIComponent(id)}`,
      { method: 'DELETE' },
    );
  },

  listAliases(projectId: string, domainId: string): Promise<{ aliases: MailAlias[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/mail/domains/${encodeURIComponent(domainId)}/aliases`);
  },
  createAlias(projectId: string, domainId: string, localPart: string, destination: string): Promise<{ alias: MailAlias; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/mail/domains/${encodeURIComponent(domainId)}/aliases`, {
      method: 'POST',
      body: { local_part: localPart, destination },
    });
  },
  deleteAlias(projectId: string, domainId: string, id: string): Promise<{ deleted: boolean; request_id: string }> {
    return request(
      `/api/v1/projects/${encodeURIComponent(projectId)}/mail/domains/${encodeURIComponent(domainId)}/aliases/${encodeURIComponent(id)}`,
      { method: 'DELETE' },
    );
  },

  listQueueLog(projectId: string, domainId: string, limit = 50): Promise<{ entries: MailQueueEntry[]; total: number; request_id: string }> {
    return request(
      `/api/v1/projects/${encodeURIComponent(projectId)}/mail/domains/${encodeURIComponent(domainId)}/queue-log?limit=${limit}`,
    );
  },
};

// ── HA platform (Phase 14) ────────────────────────────────────────────────────

export interface HAPool {
  id: string;
  project_id: string;
  name: string;
  description: string;
  mode: string;
  state: string;
  min_healthy: number;
  created_at: string;
  updated_at: string;
}

export interface HAMember {
  id: string;
  pool_id: string;
  server_id: string;
  role: string;
  state: string;
  weight: number;
  joined_at: string;
  updated_at: string;
}

export interface HAEvent {
  id: string;
  pool_id: string;
  event_type: string;
  server_id: string;
  triggered_by: string;
  details: Record<string, unknown>;
  resolved: boolean;
  occurred_at: string;
}

export interface HADrill {
  id: string;
  pool_id: string;
  drill_type: string;
  state: string;
  initiated_by: string;
  notes: string;
  started_at: string | null;
  completed_at: string | null;
  result_log: string;
  created_at: string;
  updated_at: string;
}

export const haApi = {
  listPools(projectId: string): Promise<{ pools: HAPool[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/ha/pools`);
  },
  createPool(projectId: string, name: string, description: string, mode: string, minHealthy: number): Promise<{ pool: HAPool; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/ha/pools`, {
      method: 'POST',
      body: { name, description, mode, min_healthy: minHealthy },
    });
  },
  getPool(projectId: string, id: string): Promise<{ pool: HAPool; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/ha/pools/${encodeURIComponent(id)}`);
  },
  deletePool(projectId: string, id: string): Promise<{ deleted: boolean; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/ha/pools/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },

  listMembers(projectId: string, poolId: string): Promise<{ members: HAMember[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/ha/pools/${encodeURIComponent(poolId)}/members`);
  },
  addMember(projectId: string, poolId: string, serverId: string, role: string, weight: number): Promise<{ member: HAMember; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/ha/pools/${encodeURIComponent(poolId)}/members`, {
      method: 'POST',
      body: { server_id: serverId, role, weight },
    });
  },
  removeMember(projectId: string, poolId: string, id: string): Promise<{ deleted: boolean; request_id: string }> {
    return request(
      `/api/v1/projects/${encodeURIComponent(projectId)}/ha/pools/${encodeURIComponent(poolId)}/members/${encodeURIComponent(id)}`,
      { method: 'DELETE' },
    );
  },

  startDrain(projectId: string, poolId: string, serverId: string, reason: string): Promise<{ drain_request: unknown; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/ha/pools/${encodeURIComponent(poolId)}/drain`, {
      method: 'POST',
      body: { server_id: serverId, reason },
    });
  },
  cancelDrain(projectId: string, poolId: string, id: string): Promise<{ cancelled: boolean; request_id: string }> {
    return request(
      `/api/v1/projects/${encodeURIComponent(projectId)}/ha/pools/${encodeURIComponent(poolId)}/drain/${encodeURIComponent(id)}/cancel`,
      { method: 'POST', body: {} },
    );
  },

  listEvents(projectId: string, poolId: string, limit = 50): Promise<{ events: HAEvent[]; total: number; request_id: string }> {
    return request(
      `/api/v1/projects/${encodeURIComponent(projectId)}/ha/pools/${encodeURIComponent(poolId)}/events?limit=${limit}`,
    );
  },
  resolveEvent(projectId: string, poolId: string, id: string): Promise<{ resolved: boolean; request_id: string }> {
    return request(
      `/api/v1/projects/${encodeURIComponent(projectId)}/ha/pools/${encodeURIComponent(poolId)}/events/${encodeURIComponent(id)}/resolve`,
      { method: 'POST', body: {} },
    );
  },

  listDrills(projectId: string, poolId: string): Promise<{ drills: HADrill[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/ha/pools/${encodeURIComponent(poolId)}/drills`);
  },
  createDrill(projectId: string, poolId: string, drillType: string, notes: string): Promise<{ drill: HADrill; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/ha/pools/${encodeURIComponent(poolId)}/drills`, {
      method: 'POST',
      body: { drill_type: drillType, notes },
    });
  },
  completeDrill(projectId: string, poolId: string, id: string, state: string, resultLog: string): Promise<{ state: string; request_id: string }> {
    return request(
      `/api/v1/projects/${encodeURIComponent(projectId)}/ha/pools/${encodeURIComponent(poolId)}/drills/${encodeURIComponent(id)}/complete`,
      { method: 'POST', body: { state, result_log: resultLog } },
    );
  },
};

// ── AI Copilot (Phase 15) ─────────────────────────────────────────────────────

export interface CopilotSession {
  id: string;
  project_id: string;
  user_id: string;
  state: string;
  intent: string;
  context: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface CopilotPlan {
  id: string;
  session_id: string;
  project_id: string;
  title: string;
  description: string;
  steps: unknown[];
  risk_level: string;
  state: string;
  created_by: string;
  reviewed_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface CopilotApproval {
  id: string;
  plan_id: string;
  requested_by: string;
  reviewed_by: string | null;
  state: string;
  comment: string;
  expires_at: string;
  created_at: string;
  updated_at: string;
}

export const copilotApi = {
  listSessions(projectId: string): Promise<{ sessions: CopilotSession[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/copilot/sessions`);
  },
  createSession(projectId: string, intent: string): Promise<{ session: CopilotSession; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/copilot/sessions`, {
      method: 'POST',
      body: { intent },
    });
  },
  getSession(projectId: string, id: string): Promise<{ session: CopilotSession; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/copilot/sessions/${encodeURIComponent(id)}`);
  },
  closeSession(projectId: string, id: string, state: string): Promise<{ state: string; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/copilot/sessions/${encodeURIComponent(id)}/close`, {
      method: 'POST',
      body: { state },
    });
  },

  listPlans(projectId: string): Promise<{ plans: CopilotPlan[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/copilot/plans`);
  },
  getPlan(projectId: string, id: string): Promise<{ plan: CopilotPlan; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/copilot/plans/${encodeURIComponent(id)}`);
  },
  submitPlan(projectId: string, id: string): Promise<{ plan_id: string; state?: string; approval?: CopilotApproval; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/copilot/plans/${encodeURIComponent(id)}/submit`, {
      method: 'POST',
      body: {},
    });
  },
  cancelPlan(projectId: string, id: string): Promise<{ cancelled: boolean; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/copilot/plans/${encodeURIComponent(id)}/cancel`, {
      method: 'POST',
      body: {},
    });
  },

  listApprovals(projectId: string, planId: string): Promise<{ approvals: CopilotApproval[]; total: number; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/copilot/plans/${encodeURIComponent(planId)}/approvals`);
  },
  reviewApproval(projectId: string, planId: string, id: string, state: string, comment: string): Promise<{ approval: CopilotApproval; request_id: string }> {
    return request(
      `/api/v1/projects/${encodeURIComponent(projectId)}/copilot/plans/${encodeURIComponent(planId)}/approvals/${encodeURIComponent(id)}/review`,
      { method: 'POST', body: { state, comment } },
    );
  },
};

// ── Plugin SDK (Phase 16) ─────────────────────────────────────────────────────

export interface Plugin {
  id: string;
  name: string;
  display_name: string;
  description: string;
  version: string;
  author: string;
  homepage_url: string;
  manifest: Record<string, unknown>;
  trust_level: string;
  state: string;
  signature: string;
  checksum: string;
  installed_at: string;
  updated_at: string;
}

export interface PluginPermission {
  id: string;
  plugin_id: string;
  permission: string;
  scope_kind: string;
  granted: boolean;
  granted_by: string | null;
  granted_at: string | null;
  created_at: string;
}

export const pluginsApi = {
  listPlugins(stateFilter?: string): Promise<{ plugins: Plugin[]; total: number; request_id: string }> {
    const q = stateFilter ? `?state=${encodeURIComponent(stateFilter)}` : '';
    return request(`/api/v1/plugins${q}`);
  },
  getPlugin(id: string): Promise<{ plugin: Plugin; request_id: string }> {
    return request(`/api/v1/plugins/${encodeURIComponent(id)}`);
  },
  enablePlugin(id: string): Promise<{ state: string; request_id: string }> {
    return request(`/api/v1/plugins/${encodeURIComponent(id)}/enable`, { method: 'POST', body: {} });
  },
  disablePlugin(id: string): Promise<{ state: string; request_id: string }> {
    return request(`/api/v1/plugins/${encodeURIComponent(id)}/disable`, { method: 'POST', body: {} });
  },
  uninstallPlugin(id: string): Promise<{ removed: boolean; request_id: string }> {
    return request(`/api/v1/plugins/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  setTrust(id: string, trustLevel: string): Promise<{ trust_level: string; request_id: string }> {
    return request(`/api/v1/plugins/${encodeURIComponent(id)}/trust`, { method: 'POST', body: { trust_level: trustLevel } });
  },
  listPermissions(id: string): Promise<{ permissions: PluginPermission[]; total: number; request_id: string }> {
    return request(`/api/v1/plugins/${encodeURIComponent(id)}/permissions`);
  },
  grantPermission(pluginId: string, permId: string): Promise<{ granted: boolean; request_id: string }> {
    return request(`/api/v1/plugins/${encodeURIComponent(pluginId)}/permissions/${encodeURIComponent(permId)}/grant`, {
      method: 'POST',
      body: {},
    });
  },
  quarantinePlugin(id: string, reason: string): Promise<{ quarantine: unknown; request_id: string }> {
    return request(`/api/v1/plugins/${encodeURIComponent(id)}/quarantine`, { method: 'POST', body: { reason } });
  },
};

// ── Production Hardening (Phase 17) ──────────────────────────────────────────

export interface HealthCheck {
  id: string;
  check_name: string;
  status: string;
  message: string;
  details: Record<string, unknown>;
  duration_ms: number;
  checked_at: string;
}

export interface UpgradeRecord {
  id: string;
  migration_name: string;
  from_version: string;
  to_version: string;
  applied_by: string;
  status: string;
  duration_ms: number;
  applied_at: string;
}

export interface RunbookEvent {
  id: string;
  runbook_name: string;
  event_type: string;
  outcome: string;
  performed_by: string;
  notes: string;
  duration_min: number;
  occurred_at: string;
}

export const hardeningApi = {
  listChecks(): Promise<{ overall: string; checks: HealthCheck[]; total: number; request_id: string }> {
    return request('/api/v1/health/checks');
  },
  runChecks(): Promise<{ overall: string; results: HealthCheck[]; request_id: string }> {
    return request('/api/v1/health/checks', { method: 'POST', body: {} });
  },
  listUpgrades(): Promise<{ upgrades: UpgradeRecord[]; total: number; request_id: string }> {
    return request('/api/v1/health/upgrades');
  },
  listRunbooks(): Promise<{ events: RunbookEvent[]; total: number; request_id: string }> {
    return request('/api/v1/health/runbooks');
  },
  recordRunbook(runbookName: string, eventType: string, outcome: string, notes: string, durationMin: number): Promise<{ event: RunbookEvent; request_id: string }> {
    return request('/api/v1/health/runbooks', {
      method: 'POST',
      body: { runbook_name: runbookName, event_type: eventType, outcome, notes, duration_min: durationMin },
    });
  },
};

// --- API Tokens (PRD §26.2) ---------------------------------------------------

export interface APIToken {
  id: string;
  user_id: string;
  name: string;
  kind: 'personal' | 'service';
  token_prefix: string;
  scopes: string[];
  allowed_cidrs: string[];
  expires_at?: string;
  revoked_at?: string;
  last_used_at?: string;
  created_at: string;
}

export interface CreatedAPIToken extends APIToken {
  plaintext: string;
}

export const tokenApi = {
  list(): Promise<{ tokens: APIToken[]; request_id: string }> {
    return request('/api/v1/tokens');
  },
  create(input: { name: string; kind: string; scopes?: string[]; allowed_cidrs?: string[]; expires_at?: string }): Promise<{ token: CreatedAPIToken; request_id: string }> {
    return request('/api/v1/tokens', { method: 'POST', body: input });
  },
  revoke(id: string): Promise<{ revoked: boolean; request_id: string }> {
    return request(`/api/v1/tokens/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
};

export interface PlatformUser {
  id: string;
  email: string;
  display_name: string;
  state: string;
  account_type: string;
  is_owner: boolean;
  last_login_at?: string;
  created_at: string;
}

export const userApi = {
  list(): Promise<{ users: PlatformUser[]; total: number; request_id: string }> {
    return request('/api/v1/users');
  },
  create(input: { email: string; display_name: string; password: string; account_type?: string }): Promise<{ user_id: string; request_id: string }> {
    return request('/api/v1/users', { method: 'POST', body: input });
  },
  get(id: string): Promise<{ user: PlatformUser; request_id: string }> {
    return request(`/api/v1/users/${encodeURIComponent(id)}`);
  },
  setState(id: string, state: 'active' | 'suspended'): Promise<{ user_id: string; state: string; request_id: string }> {
    return request(`/api/v1/users/${encodeURIComponent(id)}/state`, { method: 'POST', body: { state } });
  },
  bindRole(id: string, input: { role_key: string; scope_type: string; scope_id?: string }): Promise<{ bound: boolean; request_id: string }> {
    return request(`/api/v1/users/${encodeURIComponent(id)}/roles`, { method: 'POST', body: input });
  },
  unbindRole(id: string, bindingId: string): Promise<{ unbound: boolean; request_id: string }> {
    return request(`/api/v1/users/${encodeURIComponent(id)}/roles/${encodeURIComponent(bindingId)}`, { method: 'DELETE' });
  },
  impersonate(id: string, reason: string): Promise<{
    impersonated: boolean;
    user: { id: string; email: string; display_name: string };
    session_id: string;
    expires_at: string;
    request_id: string;
  }> {
    return request(`/api/v1/users/${encodeURIComponent(id)}/impersonate`, { method: 'POST', body: { reason } });
  },
};

export interface NotificationChannel {
  id: string;
  type: string;
  name: string;
  config: Record<string, unknown>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface NotifyDelivery {
  id: string;
  event: string;
  severity: string;
  channel_id: string;
  payload: Record<string, unknown>;
  state: string;
  created_at: string;
  delivered_at?: string;
}

export const notifyApi = {
  listChannels(): Promise<{ channels: NotificationChannel[]; request_id: string }> {
    return request('/api/v1/notifications/channels');
  },
  createChannel(input: { type: string; name: string; config: Record<string, unknown>; enabled?: boolean }): Promise<{ channel_id: string; request_id: string }> {
    return request('/api/v1/notifications/channels', { method: 'POST', body: input });
  },
  getChannel(id: string): Promise<{ channel: NotificationChannel; request_id: string }> {
    return request(`/api/v1/notifications/channels/${encodeURIComponent(id)}`);
  },
  updateChannel(id: string, input: { name?: string; config?: Record<string, unknown>; enabled?: boolean }): Promise<{ updated: boolean; request_id: string }> {
    return request(`/api/v1/notifications/channels/${encodeURIComponent(id)}`, { method: 'PATCH', body: input });
  },
  deleteChannel(id: string): Promise<{ deleted: boolean; request_id: string }> {
    return request(`/api/v1/notifications/channels/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  testChannel(id: string): Promise<{ enqueued: number; request_id: string }> {
    return request(`/api/v1/notifications/channels/${encodeURIComponent(id)}/test`, { method: 'POST', body: {} });
  },
  inbox(): Promise<{ deliveries: NotifyDelivery[]; request_id: string }> {
    return request('/api/v1/notifications/inbox');
  },
  markRead(id: string): Promise<{ read: boolean; request_id: string }> {
    return request(`/api/v1/notifications/inbox/${encodeURIComponent(id)}/read`, { method: 'POST', body: {} });
  },
  unreadCount(): Promise<{ unread_count: number; request_id: string }> {
    return request('/api/v1/notifications/inbox/unread');
  },
};

export interface JobSummary {
  id: string;
  type: string;
  server_id?: string;
  project_id?: string;
  state: string;
  priority: number;
  progress_current: number;
  progress_total?: number;
  current_step?: string;
  attempt_count: number;
  max_attempts: number;
  error_code?: string;
  error_summary?: string;
  created_at: string;
  lease_expires_at?: string;
}

export const jobsApi = {
  list(): Promise<{ jobs: JobSummary[]; request_id: string }> {
    return request('/api/v1/jobs');
  },
  get(id: string): Promise<{ job: JobSummary; steps: unknown[]; request_id: string }> {
    return request(`/api/v1/jobs/${encodeURIComponent(id)}`);
  },
  cancel(id: string): Promise<{ canceled: boolean; request_id: string }> {
    return request(`/api/v1/jobs/${encodeURIComponent(id)}/cancel`, { method: 'POST', body: {} });
  },
};

export interface ProjectQuota {
  id: string;
  project_id: string;
  resource: string;
  limit_value: number;
  current_value: number;
  created_at: string;
  updated_at: string;
}

export const quotaApi = {
  list(projectId: string): Promise<{ quotas: ProjectQuota[]; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/quotas`);
  },
  set(projectId: string, resource: string, limitValue: number): Promise<{ quota_id: string; request_id: string }> {
    return request(`/api/v1/projects/${encodeURIComponent(projectId)}/quotas/${encodeURIComponent(resource)}`, {
      method: 'PUT',
      body: { limit_value: limitValue },
    });
  },
};

export interface AutomationRule {
  id: string;
  name: string;
  trigger_event: string;
  condition: Record<string, unknown>;
  action_type: string;
  action_target: Record<string, unknown>;
  enabled: boolean;
  last_triggered_at?: string;
  created_at: string;
  updated_at: string;
}

export interface OutboundWebhook {
  id: string;
  name: string;
  target_url: string;
  event_filter: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event: string;
  payload: Record<string, unknown>;
  status: string;
  status_code?: number;
  error_message?: string;
  attempt_count: number;
  max_attempts: number;
  delivered_at?: string;
  created_at: string;
}

export const automationApi = {
  listRules(): Promise<{ rules: AutomationRule[]; request_id: string }> {
    return request('/api/v1/automation/rules');
  },
  createRule(input: { name: string; trigger_event: string; condition?: Record<string, unknown>; action_type: string; action_target?: Record<string, unknown>; enabled?: boolean }): Promise<{ rule_id: string; request_id: string }> {
    return request('/api/v1/automation/rules', { method: 'POST', body: input });
  },
  updateRule(id: string, input: { name?: string; trigger_event?: string; condition?: Record<string, unknown>; action_type?: string; enabled?: boolean }): Promise<{ updated: boolean; request_id: string }> {
    return request(`/api/v1/automation/rules/${encodeURIComponent(id)}`, { method: 'PATCH', body: input });
  },
  deleteRule(id: string): Promise<{ deleted: boolean; request_id: string }> {
    return request(`/api/v1/automation/rules/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  testRule(id: string): Promise<{ simulated: boolean; rule: AutomationRule; would_action: string; request_id: string }> {
    return request(`/api/v1/automation/rules/${encodeURIComponent(id)}/test`, { method: 'POST', body: {} });
  },
  listWebhooks(): Promise<{ webhooks: OutboundWebhook[]; request_id: string }> {
    return request('/api/v1/webhooks/outbound');
  },
  createWebhook(input: { name: string; target_url: string; event_filter?: string[]; enabled?: boolean }): Promise<{ webhook_id: string; signing_secret: string; request_id: string }> {
    return request('/api/v1/webhooks/outbound', { method: 'POST', body: input });
  },
  updateWebhook(id: string, input: { name?: string; target_url?: string; enabled?: boolean }): Promise<{ updated: boolean; request_id: string }> {
    return request(`/api/v1/webhooks/outbound/${encodeURIComponent(id)}`, { method: 'PATCH', body: input });
  },
  deleteWebhook(id: string): Promise<{ deleted: boolean; request_id: string }> {
    return request(`/api/v1/webhooks/outbound/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  getDeliveries(id: string): Promise<{ deliveries: WebhookDelivery[]; request_id: string }> {
    return request(`/api/v1/webhooks/outbound/${encodeURIComponent(id)}/deliveries`);
  },
  testWebhook(id: string): Promise<{ enqueued: boolean; target_url: string; delivery_id: string; request_id: string }> {
    return request(`/api/v1/webhooks/outbound/${encodeURIComponent(id)}/test`, { method: 'POST', body: {} });
  },
};

export interface AttackModeStatus {
  server_id: string;
  enabled: boolean;
  rate_limit_multiplier: number;
  challenge_suspicious: boolean;
  restrict_expensive: boolean;
  activated_by?: string;
  activated_at?: string;
  updated_at: string;
}

export const attackModeApi = {
  get(serverId: string): Promise<{ attack_mode: AttackModeStatus; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/security/attack-mode`);
  },
  enable(serverId: string): Promise<{ enabled: boolean; server_id: string; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/security/attack-mode`, { method: 'POST', body: {} });
  },
  disable(serverId: string): Promise<{ enabled: boolean; server_id: string; request_id: string }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/security/attack-mode`, { method: 'DELETE' });
  },
};

// --- Terminal API (PRD §17.4) ------------------------------------------------
// Bounded task runner: exec runs only allowlisted commands.
// SSE audit stream: EventSource('/api/v1/servers/{id}/terminal/stream') for read-only.

export const terminalApi = {
  exec(
    serverId: string,
    command: string,
    args: string[] = [],
    mode = 'project',
  ): Promise<{
    server_id: string;
    command: string;
    stdout: string;
    stderr: string;
    exit_code: number;
    error?: string;
    request_id: string;
  }> {
    return request(`/api/v1/servers/${encodeURIComponent(serverId)}/terminal/exec`, {
      method: 'POST',
      body: { command, args, mode },
    });
  },
  // Returns a URL for EventSource (SSE) — construct in the component.
  streamUrl(serverId: string): string {
    return `/api/v1/servers/${encodeURIComponent(serverId)}/terminal/stream`;
  },
};

// --- Audit Log API (PRD §36) -------------------------------------------------

export interface AuditEventItem {
  id: string;
  seq: number;
  actor_type: string;
  actor_id?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  result: 'success' | 'failure' | 'denied';
  source_ip?: string;
  occurred_at: string;
}

export const auditLogApi = {
  list(params?: {
    action?: string;
    resource_type?: string;
    result?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ events: AuditEventItem[]; total: number; request_id: string }> {
    const q = new URLSearchParams();
    if (params?.action) q.set('action', params.action);
    if (params?.resource_type) q.set('resource_type', params.resource_type);
    if (params?.result) q.set('result', params.result);
    if (params?.limit) q.set('limit', String(params.limit));
    if (params?.offset) q.set('offset', String(params.offset));
    const qs = q.toString() ? `?${q.toString()}` : '';
    return request(`/api/v1/audit-events${qs}`);
  },
  csvExportUrl(params?: { action?: string; resource_type?: string; result?: string }): string {
    const q = new URLSearchParams({ format: 'csv' });
    if (params?.action) q.set('action', params.action);
    if (params?.resource_type) q.set('resource_type', params.resource_type);
    if (params?.result) q.set('result', params.result);
    return `/api/v1/audit-events?${q.toString()}`;
  },
};

// --- Revisions API (PRD §36) -------------------------------------------------

export interface RevisionSummary {
  id: string;
  resource_type: string;
  resource_id: string;
  actor_type: string;
  actor_id?: string;
  candidate_hash: string;
  state: string;
  git_sync_state: string;
  git_commit_sha?: string;
  created_at: string;
  applied_at?: string;
}

export const revisionApi = {
  list(params?: {
    resource_type?: string;
    resource_id?: string;
    state?: string;
    limit?: number;
  }): Promise<{ revisions: RevisionSummary[]; total: number; request_id: string }> {
    const q = new URLSearchParams();
    if (params?.resource_type) q.set('resource_type', params.resource_type);
    if (params?.resource_id) q.set('resource_id', params.resource_id);
    if (params?.state) q.set('state', params.state);
    if (params?.limit) q.set('limit', String(params.limit));
    const qs = q.toString() ? `?${q.toString()}` : '';
    return request(`/api/v1/revisions${qs}`);
  },
  get(id: string): Promise<{ revision: any; request_id: string }> {
    return request(`/api/v1/revisions/${encodeURIComponent(id)}`);
  },
};


