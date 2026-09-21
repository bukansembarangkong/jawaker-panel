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

export const api = {
  getVersion: (): Promise<VersionInfo> => request<VersionInfo>('/api/v1/version'),
  getHealth: (): Promise<HealthInfo> => request<HealthInfo>('/healthz'),

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
