/**
 * Minimal API client for the JAWAKER controller.
 *
 * Conventions enforced here (API.md):
 *  - every request may carry a client-generated correlation ID and the
 *    server's X-Request-ID is surfaced on errors for supportability;
 *  - errors are parsed from the canonical envelope, never from raw bodies;
 *  - no secrets, no credentials other than same-origin cookies later.
 *
 * TanStack Query adoption is deferred to Phase 1 when real server state
 * exists; this module is the single fetch boundary until then.
 */

export const REQUEST_ID_HEADER = 'X-Request-ID';

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

function newCorrelationId(): string {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return `req_ui_${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      Accept: 'application/json',
      [REQUEST_ID_HEADER]: newCorrelationId(),
      ...init?.headers,
    },
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
    throw new ApiError(response.status, envelope, `Request failed with status ${response.status}`);
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

export const api = {
  getVersion: (): Promise<VersionInfo> => request<VersionInfo>('/api/v1/version'),
  getHealth: (): Promise<HealthInfo> => request<HealthInfo>('/healthz'),
};
