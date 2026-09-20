import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import App from './App';
import { ApiError, type ApiErrorEnvelope } from './api/client';

const versionPayload = {
  version: '0.1.0-dev',
  commit: 'abc1234',
  build_time: '2026-09-19T00:00:00Z',
};

const ownerSession = {
  user: { id: 'u-1', email: 'owner@example.test', display_name: 'Owner', is_owner: true },
  session_id: 's-1',
  elevated: false,
  permissions: { global: ['users.read', 'security.read'], scoped: [] },
};

const mfaEnrolled = { totp_enrolled: true, totp_enrollment_pending: false, recovery_codes_remaining: 8 };

/**
 * Route responses by path so one mock can serve the whole shell. The real app
 * primes CSRF, then reads session/version/mfa; a test that only stubs one
 * endpoint would fail for a reason unrelated to what it checks.
 */
function mockApi(overrides: Record<string, unknown> = {}) {
  const routes: Record<string, unknown> = {
    '/api/v1/auth/csrf': { csrf_token: 'tok_1' },
    '/api/v1/version': versionPayload,
    '/api/v1/auth/session': null,
    '/api/v1/auth/bootstrap': { requires_bootstrap: false },
    '/api/v1/auth/mfa': mfaEnrolled,
    ...overrides,
  };
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    void init;
    const body = routes[path];
    if (body === null || body === undefined) {
      const envelope: ApiErrorEnvelope = {
        error: { code: 'unauthorized', message: 'Authentication required.', retryable: false },
        request_id: 'req_srv_401',
      };
      return {
        ok: false,
        status: 401,
        headers: new Headers({ 'X-Request-ID': 'req_srv_401' }),
        json: async () => envelope,
        clone() {
          return this;
        },
      };
    }
    return {
      ok: true,
      status: 200,
      headers: new Headers({ 'X-Request-ID': 'req_srv_1' }),
      json: async () => body,
      clone() {
        return this;
      },
    };
  });
  global.fetch = fetchMock as unknown as typeof fetch;
  return fetchMock;
}

function mockNetworkError() {
  global.fetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch')) as unknown as typeof fetch;
}

beforeEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
  window.location.hash = '';
});

describe('unreachable controller', () => {
  it('reports the fault instead of showing a login form', async () => {
    mockNetworkError();
    render(<App />);
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
    expect(screen.getByText('Cannot reach the controller')).toBeInTheDocument();
    // A login form here would invite credentials into a panel that cannot
    // check them, so its absence is the assertion that matters.
    expect(screen.queryByRole('button', { name: /sign in/i })).not.toBeInTheDocument();
  });

  it('shows a retry that recovers', async () => {
    const user = userEvent.setup();
    mockNetworkError();
    render(<App />);
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());

    mockApi({ '/api/v1/auth/session': ownerSession });
    await user.click(screen.getByRole('button', { name: /retry/i }));
    await waitFor(() => expect(screen.getByText('Signed in as')).toBeInTheDocument());
  });
});

describe('anonymous state', () => {
  it('shows the login form when no session exists', async () => {
    mockApi({ '/api/v1/auth/session': null });
    render(<App />);
    await waitFor(() => expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument());
    expect(screen.getByText(/sign in to the control panel/i)).toBeInTheDocument();
  });

  it('offers bootstrap when the installation has no owner', async () => {
    mockApi({
      '/api/v1/auth/session': null,
      '/api/v1/auth/bootstrap': { requires_bootstrap: true },
    });
    render(<App />);
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /create platform owner/i })).toBeInTheDocument(),
    );
    expect(screen.getByText(/this installation has no owner yet/i)).toBeInTheDocument();
  });
});

describe('authenticated shell', () => {
  it('renders navigation, session metrics, and the owner MFA action', async () => {
    mockApi({ '/api/v1/auth/session': ownerSession, '/api/v1/auth/mfa': { ...mfaEnrolled, totp_enrolled: false, recovery_codes_remaining: 0 } });
    render(<App />);
    await waitFor(() => expect(screen.getByText('Overview')).toBeInTheDocument());
    expect(screen.getByText('Security')).toBeInTheDocument();
    expect(screen.getByText('owner@example.test')).toBeInTheDocument();
    expect(screen.getByText('Platform owner')).toBeInTheDocument();
    // The highest-priority action in this build is the owner lacking a factor.
    expect(screen.getByText('The platform owner has no second factor')).toBeInTheDocument();
  });

  it('flags a critically low recovery-code count', async () => {
    mockApi({
      '/api/v1/auth/session': ownerSession,
      '/api/v1/auth/mfa': { totp_enrolled: true, totp_enrollment_pending: false, recovery_codes_remaining: 0 },
    });
    render(<App />);
    await waitFor(() => expect(screen.getByText('No recovery codes remain')).toBeInTheDocument());
  });

  it('navigates to Security via the hash', async () => {
    const user = userEvent.setup();
    mockApi({ '/api/v1/auth/session': ownerSession });
    render(<App />);
    await waitFor(() => expect(screen.getByText('Security')).toBeInTheDocument());

    await user.click(screen.getByText('Security'));
    expect(window.location.hash).toBe('#/security');
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /recovery codes/i })).toBeInTheDocument(),
    );
  });

  it('signs out and returns to the login form', async () => {
    const user = userEvent.setup();
    mockApi({ '/api/v1/auth/session': ownerSession, '/api/v1/auth/logout': { status: 'logged_out' } });
    render(<App />);
    await waitFor(() => expect(screen.getByText('Overview')).toBeInTheDocument());

    await user.click(screen.getByRole('button', { name: /sign out/i }));
    await waitFor(() => expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument());
  });
});

describe('login flow', () => {
  it('prompts for the second factor when the server asks for one', async () => {
    const user = userEvent.setup();
    const envelope: ApiErrorEnvelope = {
      error: { code: 'totp_required', message: 'A two-factor code is required.', retryable: false },
      request_id: 'req_2fa',
    };

    // Stateful rather than call-counted: the shell reads /auth/session on mount
    // AND after login, and only a flag can tell those two apart.
    let signedIn = false;
    let secondFactorSeen = false;

    const notFound = {
      ok: false,
      status: 401,
      headers: new Headers(),
      json: async () => ({ error: { code: 'unauthorized', message: 'x', retryable: false } }),
      clone() {
        return this;
      },
    };
    const ok = (body: unknown) => ({
      ok: true,
      status: 200,
      headers: new Headers({ 'X-Request-ID': 'req_1' }),
      json: async () => body,
      clone() {
        return this;
      },
    });

    global.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith('/auth/csrf')) {
        return ok({ csrf_token: 'tok_1' });
      }
      if (path.endsWith('/version')) {
        return ok(versionPayload);
      }
      if (path.endsWith('/auth/bootstrap')) {
        return ok({ requires_bootstrap: false });
      }
      if (path.endsWith('/auth/session')) {
        return signedIn ? ok(ownerSession) : notFound;
      }
      if (path.endsWith('/auth/mfa')) {
        return ok(mfaEnrolled);
      }
      if (path.endsWith('/auth/login')) {
        // The first attempt carries only a password, so the server asks for the
        // factor. The second carries it and authenticates.
        if (!secondFactorSeen) {
          return {
            ok: false,
            status: 401,
            headers: new Headers({ 'X-Request-ID': 'req_2fa' }),
            json: async () => envelope,
            clone() {
              return this;
            },
          };
        }
        signedIn = true;
        return ok({ user: ownerSession.user, session_id: 's-2', csrf_token: 'tok_2' });
      }
      return notFound;
    }) as unknown as typeof fetch;

    render(<App />);
    await waitFor(() => expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument());

    await user.type(screen.getByLabelText(/email address/i), 'owner@example.test');
    await user.type(screen.getByLabelText(/password/i), 'correct horse battery staple');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    // The prompt appears only after the server says so; the password failure
    // itself is not rendered as an error, because the password was accepted.
    await waitFor(() => expect(screen.getByLabelText(/two-factor code/i)).toBeInTheDocument());
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();

    await user.type(screen.getByLabelText(/two-factor code/i), '123456');
    // The next login attempt carries the factor, so the mock now authenticates.
    secondFactorSeen = true;
    await user.click(screen.getByRole('button', { name: /sign in/i }));
    await waitFor(() => expect(screen.getByText('Overview')).toBeInTheDocument());
  });

  it('surfaces a real sign-in failure with its code and request id', async () => {
    const user = userEvent.setup();
    const envelope: ApiErrorEnvelope = {
      error: {
        code: 'invalid_credentials',
        message: 'The email address or password is incorrect.',
        retryable: false,
      },
      request_id: 'req_bad',
    };
    global.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith('/auth/login')) {
        return {
          ok: false,
          status: 401,
          headers: new Headers({ 'X-Request-ID': 'req_bad' }),
          json: async () => envelope,
          clone() {
            return this;
          },
        };
      }
      const body = path.endsWith('/version')
        ? versionPayload
        : path.endsWith('/auth/csrf')
          ? { csrf_token: 'tok_1' }
          : path.endsWith('/auth/bootstrap')
            ? { requires_bootstrap: false }
            : null;
      if (body === null) {
        return {
          ok: false,
          status: 401,
          headers: new Headers(),
          json: async () => ({ error: { code: 'unauthorized', message: 'x', retryable: false } }),
          clone() {
            return this;
          },
        };
      }
      return {
        ok: true,
        status: 200,
        headers: new Headers({ 'X-Request-ID': 'req_1' }),
        json: async () => body,
        clone() {
          return this;
        },
      };
    }) as unknown as typeof fetch;

    render(<App />);
    await waitFor(() => expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument());

    await user.type(screen.getByLabelText(/email address/i), 'owner@example.test');
    await user.type(screen.getByLabelText(/password/i), 'wrong');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
    expect(screen.getByText('invalid_credentials')).toBeInTheDocument();
    expect(screen.getByText('req_bad')).toBeInTheDocument();
  });
});

describe('theme control', () => {
  it('cycles system -> light -> dark -> system and persists', async () => {
    mockApi({ '/api/v1/auth/session': ownerSession });
    const user = userEvent.setup();
    render(<App />);
    await waitFor(() => expect(screen.getByText('Overview')).toBeInTheDocument());

    const toggle = screen.getByRole('button', { name: /^theme:/i });
    expect(toggle).toHaveTextContent('Theme: system');
    expect(document.documentElement).not.toHaveAttribute('data-theme');

    await user.click(toggle);
    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
    expect(localStorage.getItem('jawaker.theme')).toBe('light');

    await user.click(toggle);
    expect(document.documentElement).toHaveAttribute('data-theme', 'dark');

    await user.click(toggle);
    expect(document.documentElement).not.toHaveAttribute('data-theme');
  });

  it('restores a persisted theme on mount', async () => {
    localStorage.setItem('jawaker.theme', 'dark');
    mockApi({ '/api/v1/auth/session': ownerSession });
    render(<App />);
    await waitFor(() => expect(screen.getByText('Overview')).toBeInTheDocument());
    expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
  });
});

describe('ApiError parsing', () => {
  it('exposes code, retryable, and request id from an envelope response', async () => {
    const headers = new Headers({ 'X-Request-ID': 'req_env_1' });
    global.fetch = vi.fn(async () => ({
      ok: false,
      status: 403,
      headers,
      json: async () => ({
        error: { code: 'forbidden', message: 'Denied.', retryable: false },
        request_id: 'req_env_1',
      }),
      clone() {
        return this;
      },
    })) as unknown as typeof fetch;

    const { api } = await import('./api/client');
    await expect(api.getVersion()).rejects.toMatchObject({
      name: 'ApiError',
      status: 403,
      code: 'forbidden',
      requestId: 'req_env_1',
    });
  });

  it('handles non-JSON error bodies without throwing', async () => {
    global.fetch = vi.fn(async () => ({
      ok: false,
      status: 502,
      headers: new Headers(),
      json: async () => {
        throw new Error('not json');
      },
      clone() {
        return this;
      },
    })) as unknown as typeof fetch;

    const { api } = await import('./api/client');
    await expect(api.getVersion()).rejects.toBeInstanceOf(ApiError);
  });

  it('sends a client correlation id and a CSRF header on mutations', async () => {
    const fetchMock = mockApi({ '/api/v1/auth/logout': { status: 'logged_out' } });
    const { api, primeCsrf } = await import('./api/client');

    await primeCsrf();
    const [csrfPath] = fetchMock.mock.calls[0];
    expect(csrfPath).toBe('/api/v1/auth/csrf');

    await api.logout();
    const logoutCall = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(logoutCall[0]).toBe('/api/v1/auth/logout');
    const headers = logoutCall[1].headers as Record<string, string>;
    expect(headers['X-Request-ID']).toMatch(/^req_ui_[0-9a-f]{24}$/);
    expect(headers['X-CSRF-Token']).toBe('tok_1');
  });
});
