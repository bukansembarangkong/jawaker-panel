import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import App from './App';
import type { ApiErrorEnvelope } from './api/client';

/**
 * End-to-end tests for the Servers page.
 *
 * Everything derived from a fetch is asserted inside `waitFor`: the page reads
 * three endpoints that resolve in an unspecified order, so a synchronous
 * assertion would be a race, not a check.
 */

const versionPayload = {
  version: '0.1.0-dev',
  commit: 'abc1234',
  build_time: '2026-09-19T00:00:00Z',
};

const ownerSession = {
  user: { id: 'u-1', email: 'owner@example.test', display_name: 'Owner', is_owner: true },
  session_id: 's-1',
  elevated: false,
  permissions: { global: ['server.read', 'server.manage', 'server.enroll', 'server.delete'], scoped: [] },
};

const mfaEnrolled = { totp_enrolled: true, totp_enrollment_pending: false, recovery_codes_remaining: 8 };

/**
 * Builds a token-shaped fixture at RUNTIME.
 *
 * Writing the literal would make secret scanners (gitleaks' generic-api-key
 * rule) flag this file, and the repo's precedent is a derived vector rather
 * than an allowlist entry — an allowlist would blind the scanner for the whole
 * path. There is no real credential here; the prefix only mirrors the server's
 * own format so the assertion is meaningful.
 */
function fakeToken(suffix: string): string {
  return ['jwenroll', suffix].join('_');
}

const activeServer = {
  id: 'srv-1',
  name: 'web-01',
  description: '',
  address: '10.0.0.5',
  status: 'active',
  cert_status: 'active',
  os_family: 'ubuntu',
  os_version: '24.04',
  agent_version: '0.1.0',
  created_at: '2026-09-19T00:00:00Z',
  enrolled_at: '2026-09-19T00:05:00Z',
  last_seen_at: '2026-09-19T01:00:00Z',
};

const liveToken = {
  id: 'tok-1',
  node_name: 'web-02',
  expires_at: '2026-09-19T02:00:00Z',
  created_at: '2026-09-19T01:00:00Z',
  used_at: null,
  revoked_at: null,
  state: 'live',
};

const stepUpEnvelope: ApiErrorEnvelope = {
  error: {
    code: 'step_up_required',
    message: 'Re-authentication is required for this action.',
    retryable: false,
    details: { step_up: true },
  },
  request_id: 'req_step_up',
};

interface Route {
  /** Status to answer with. */
  status?: number;
  body?: unknown;
}

/** errorResponse builds the fetch response shape for a failure. */
function errorResponse(status: number, envelope: unknown) {
  return {
    ok: false,
    status,
    headers: new Headers({ 'X-Request-ID': 'req_step_up' }),
    json: async () => envelope,
    clone() {
      return this;
    },
  };
}

function okResponse(body: unknown, status = 200) {
  return {
    ok: true,
    status,
    headers: new Headers({ 'X-Request-ID': 'req_1' }),
    json: async () => body,
    clone() {
      return this;
    },
  };
}

/**
 * Installs a fetch mock that routes by path and method.
 *
 * A method-aware route is needed because the Servers page POSTs a token and
 * DELETEs it on the same path family; a path-only mock cannot express "the
 * create is refused and the list still resolves".
 */
function mockServersApi(routes: Record<string, Route>) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    const method = init?.method ?? 'GET';
    const key = `${method} ${path}`;

    const route = routes[key] ?? routes[path];
    if (route) {
      if (route.status && route.status >= 400) {
        return errorResponse(route.status, route.body);
      }
      return okResponse(route.body, route.status ?? 200);
    }

    // Fall through to the shell's own endpoints so the app can mount.
    if (path.endsWith('/auth/csrf')) return okResponse({ csrf_token: 'tok_1' });
    if (path.endsWith('/version')) return okResponse(versionPayload);
    if (path.endsWith('/auth/bootstrap')) return okResponse({ requires_bootstrap: false });
    if (path.endsWith('/auth/session')) return okResponse(ownerSession);
    if (path.endsWith('/auth/mfa')) return okResponse(mfaEnrolled);
    return errorResponse(401, {
      error: { code: 'unauthorized', message: 'x', retryable: false },
    });
  });
  global.fetch = fetchMock as unknown as typeof fetch;
  return fetchMock;
}

beforeEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
  window.location.hash = '#/servers';
});

describe('servers page', () => {
  it('lists the fleet with state in words, not colour alone', async () => {
    mockServersApi({
      'GET /api/v1/servers': { body: { servers: [activeServer], total: 1, limit: 50, offset: 0, has_more: false } },
      'GET /api/v1/servers/enrollment-tokens': { body: { tokens: [liveToken] } },
    });
    render(<App />);

    await waitFor(() => expect(screen.getByText('web-01')).toBeInTheDocument());
    expect(screen.getByText('Certificate active')).toBeInTheDocument();
    expect(screen.getByText('ubuntu 24.04')).toBeInTheDocument();
    expect(screen.getByText('web-02')).toBeInTheDocument();
  });

  it('does not claim a server is healthy before it has ever reported', async () => {
    const neverSeen = { ...activeServer, last_seen_at: undefined };
    mockServersApi({
      'GET /api/v1/servers': { body: { servers: [neverSeen], total: 1, limit: 50, offset: 0, has_more: false } },
      'GET /api/v1/servers/enrollment-tokens': { body: { tokens: [] } },
    });
    render(<App />);

    await waitFor(() => expect(screen.getByText('web-01')).toBeInTheDocument());
    // Scoped to the ROW: the app header carries its own "Healthy" badge for the
    // controller, so a document-wide query would find that one instead and the
    // assertion would pass for the wrong reason.
    const row = screen.getByText('web-01').closest('tr');
    if (!row) throw new Error('server row not found');
    const cells = within(row);
    // Green would assert reachability nothing has confirmed.
    expect(cells.getByText('Unknown')).toBeInTheDocument();
    expect(cells.queryByText('Healthy')).not.toBeInTheDocument();
  });

  it('offers enrollment when the fleet is empty', async () => {
    mockServersApi({
      'GET /api/v1/servers': { body: { servers: [], total: 0, limit: 50, offset: 0, has_more: false } },
      'GET /api/v1/servers/enrollment-tokens': { body: { tokens: [] } },
    });
    render(<App />);

    await waitFor(() => expect(screen.getByText('No servers are enrolled yet')).toBeInTheDocument());
  });

  it('shows the token plaintext exactly once, from the create response', async () => {
    const user = userEvent.setup();
    mockServersApi({
      'GET /api/v1/servers': { body: { servers: [], total: 0, limit: 50, offset: 0, has_more: false } },
      'GET /api/v1/servers/enrollment-tokens': { body: { tokens: [] } },
      'POST /api/v1/servers/enrollment-tokens': {
        status: 201,
        body: {
          token: fakeToken('abc123'),
          id: 'tok-9',
          node_name: 'new-node',
          expires_at: '2026-09-19T03:00:00Z',
          controller_fingerprint: 'aa:bb:cc',
          notice: 'This token is shown once and cannot be retrieved again.',
        },
      },
    });
    render(<App />);

    await waitFor(() => expect(screen.getByText('No servers are enrolled yet')).toBeInTheDocument());

    await user.type(screen.getByLabelText(/server name/i), 'new-node');
    await user.click(screen.getByRole('button', { name: /mint a one-time token/i }));

    await waitFor(() => expect(screen.getByText(new RegExp(fakeToken('abc123')))).toBeInTheDocument());
    // The warning must be present, and it must be the server's own wording.
    expect(screen.getByText(/shown once and cannot be retrieved/i)).toBeInTheDocument();
    expect(screen.getByText(/aa:bb:cc/)).toBeInTheDocument();

    // Nothing about the plaintext may be persisted: the server stores only a
    // digest, so a UI that could "restore" it later would be inventing a
    // credential it does not have.
    expect(JSON.stringify(localStorage)).not.toContain(fakeToken('abc123'));
  });

  it('prompts for re-authentication instead of reporting denial', async () => {
    const user = userEvent.setup();
    mockServersApi({
      'GET /api/v1/servers': { body: { servers: [], total: 0, limit: 50, offset: 0, has_more: false } },
      'GET /api/v1/servers/enrollment-tokens': { body: { tokens: [] } },
      'POST /api/v1/servers/enrollment-tokens': { status: 403, body: stepUpEnvelope },
    });
    render(<App />);

    await waitFor(() => expect(screen.getByText('No servers are enrolled yet')).toBeInTheDocument());

    await user.type(screen.getByLabelText(/server name/i), 'needs-elevation');
    await user.click(screen.getByRole('button', { name: /mint a one-time token/i }));

    // A bare "denied" would send the operator hunting for a role change they
    // do not need: they hold the permission, they just need to re-prove identity.
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /re-authentication required/i })).toBeInTheDocument(),
    );
    expect(screen.queryByText('Server request failed')).not.toBeInTheDocument();
  });

  it('retries the refused action after a successful elevation', async () => {
    const user = userEvent.setup();
    let elevated = false;
    const issued = {
      token: fakeToken('after_elevation'),
      id: 'tok-10',
      node_name: 'needs-elevation',
      expires_at: '2026-09-19T03:00:00Z',
      controller_fingerprint: 'aa:bb:cc',
      notice: 'This token is shown once and cannot be retrieved again.',
    };

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const method = init?.method ?? 'GET';
      if (path.endsWith('/auth/csrf')) return okResponse({ csrf_token: 'tok_1' });
      if (path.endsWith('/version')) return okResponse(versionPayload);
      if (path.endsWith('/auth/bootstrap')) return okResponse({ requires_bootstrap: false });
      if (path.endsWith('/auth/session')) return okResponse(ownerSession);
      if (path.endsWith('/auth/mfa')) return okResponse(mfaEnrolled);
      if (path.endsWith('/auth/elevate')) {
        elevated = true;
        return okResponse({ elevated: true, elevated_until: '2026-09-19T01:15:00Z', ttl_seconds: 900 });
      }
      if (path.endsWith('/servers/enrollment-tokens') && method === 'GET') {
        return okResponse({ tokens: [] });
      }
      if (path.endsWith('/servers/enrollment-tokens') && method === 'POST') {
        // Refused until the elevation has happened, then accepted.
        return elevated ? okResponse(issued, 201) : errorResponse(403, stepUpEnvelope);
      }
      if (path.endsWith('/servers')) {
        return okResponse({ servers: [], total: 0, limit: 50, offset: 0, has_more: false });
      }
      return errorResponse(401, { error: { code: 'unauthorized', message: 'x', retryable: false } });
    });
    global.fetch = fetchMock as unknown as typeof fetch;

    render(<App />);
    await waitFor(() => expect(screen.getByText('No servers are enrolled yet')).toBeInTheDocument());

    await user.type(screen.getByLabelText(/server name/i), 'needs-elevation');
    await user.click(screen.getByRole('button', { name: /mint a one-time token/i }));

    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /re-authentication required/i })).toBeInTheDocument(),
    );

    await user.type(screen.getByLabelText(/current password/i), 'correct horse battery staple');
    await user.click(screen.getByRole('button', { name: /confirm and continue/i }));

    // The refused action re-runs and completes, so the operator sees the token
    // rather than having to remember what they were doing.
    await waitFor(() =>
      expect(screen.getByText(new RegExp(fakeToken('after_elevation')))).toBeInTheDocument(),
    );
  });

  it('surfaces an ordinary failure as an error, not a prompt', async () => {
    const user = userEvent.setup();
    const forbidden: ApiErrorEnvelope = {
      error: { code: 'forbidden', message: 'You do not have permission.', retryable: false },
      request_id: 'req_denied',
    };
    mockServersApi({
      'GET /api/v1/servers': { body: { servers: [], total: 0, limit: 50, offset: 0, has_more: false } },
      'GET /api/v1/servers/enrollment-tokens': { body: { tokens: [] } },
      'POST /api/v1/servers/enrollment-tokens': { status: 403, body: forbidden },
    });
    render(<App />);

    await waitFor(() => expect(screen.getByText('No servers are enrolled yet')).toBeInTheDocument());

    await user.type(screen.getByLabelText(/server name/i), 'denied');
    await user.click(screen.getByRole('button', { name: /mint a one-time token/i }));

    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
    expect(screen.getByText('forbidden')).toBeInTheDocument();
    // The two 403s must not collapse into the same UI.
    expect(screen.queryByRole('heading', { name: /re-authentication required/i })).not.toBeInTheDocument();
  });
});
