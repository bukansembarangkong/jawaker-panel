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
};
