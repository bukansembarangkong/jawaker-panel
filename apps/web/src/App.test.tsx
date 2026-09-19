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

function mockFetchOk(payload: unknown) {
  return vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    headers: new Headers({ 'X-Request-ID': 'req_srv_1' }),
    json: async () => payload,
    clone() {
      return this;
    },
  });
}

function mockFetchError(status: number, envelope: ApiErrorEnvelope | null) {
  const headers = new Headers();
  if (envelope?.request_id) {
    headers.set('X-Request-ID', envelope.request_id);
  }
  return vi.fn().mockResolvedValue({
    ok: false,
    status,
    headers,
    json: envelope
      ? async () => envelope
      : async () => {
          throw new Error('not json');
        },
    clone() {
      return this;
    },
  });
}

beforeEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
});

describe('App shell', () => {
  it('renders brand and phase information', async () => {
    global.fetch = mockFetchOk(versionPayload);
    render(<App />);
    expect(screen.getByRole('heading', { name: /jawaker/i })).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByText('Phase 0 — engineering foundation')).toBeInTheDocument(),
    );
  });

  it('shows loading state before the version resolves', async () => {
    let resolveFetch!: (value: unknown) => void;
    global.fetch = vi
      .fn()
      .mockReturnValue(new Promise((resolve) => (resolveFetch = resolve)));
    render(<App />);
    expect(screen.getByRole('status')).toHaveTextContent(/checking controller/i);

    // Settle the pending request with the real payload and wait for the
    // state transition inside act().
    resolveFetch({
      ok: true,
      status: 200,
      headers: new Headers({ 'X-Request-ID': 'req_srv_1' }),
      json: async () => versionPayload,
      clone() {
        return this;
      },
    });
    await waitFor(() => expect(screen.getByText('Connected')).toBeInTheDocument());
  });

  it('shows connected state with controller version metadata', async () => {
    global.fetch = mockFetchOk(versionPayload);
    render(<App />);
    await waitFor(() => expect(screen.getByText('Connected')).toBeInTheDocument());
    expect(screen.getByText('0.1.0-dev')).toBeInTheDocument();
    expect(screen.getByText('abc1234')).toBeInTheDocument();
  });

  it('shows error state with code and request id from the envelope', async () => {
    global.fetch = mockFetchError(503, {
      error: {
        code: 'database_unavailable',
        message: 'The control-plane database is currently unavailable.',
        retryable: true,
      },
      request_id: 'req_srv_42',
    });
    render(<App />);
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
    expect(screen.getByText('Disconnected')).toBeInTheDocument();
    expect(screen.getByText('database_unavailable')).toBeInTheDocument();
    expect(screen.getByText('req_srv_42')).toBeInTheDocument();
    expect(screen.getByText('true')).toBeInTheDocument();
  });

  it('falls back to a network error state when fetch rejects', async () => {
    global.fetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));
    render(<App />);
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
    expect(screen.getByText('network_error')).toBeInTheDocument();
    expect(screen.getByText(/cannot reach the controller/i)).toBeInTheDocument();
  });

  it('retries on demand after a failure', async () => {
    const user = userEvent.setup();
    global.fetch = vi.fn().mockRejectedValueOnce(new TypeError('Failed to fetch'));
    render(<App />);
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());

    global.fetch = mockFetchOk(versionPayload);
    await user.click(screen.getByRole('button', { name: /retry/i }));
    await waitFor(() => expect(screen.getByText('Connected')).toBeInTheDocument());
  });
});

describe('theme control', () => {
  it('cycles system -> light -> dark -> system and persists', async () => {
    global.fetch = mockFetchOk(versionPayload);
    const user = userEvent.setup();
    render(<App />);

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
    global.fetch = mockFetchOk(versionPayload);
    render(<App />);
    expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
    expect(screen.getByRole('button', { name: /^theme:/i })).toHaveTextContent('Theme: dark');
    // Let the version fetch settle inside act() to avoid state-update warnings.
    await waitFor(() => expect(screen.getByText('Connected')).toBeInTheDocument());
  });
});

describe('ApiError parsing', () => {
  it('exposes code, retryable, and request id from an envelope response', async () => {
    global.fetch = mockFetchError(403, {
      error: { code: 'forbidden', message: 'Denied.', retryable: false },
      request_id: 'req_env_1',
    });
    const { api } = await import('./api/client');
    await expect(api.getVersion()).rejects.toMatchObject({
      name: 'ApiError',
      status: 403,
      code: 'forbidden',
      requestId: 'req_env_1',
    });
  });

  it('handles non-JSON error bodies without throwing', async () => {
    global.fetch = mockFetchError(502, null);
    const { api } = await import('./api/client');
    await expect(api.getVersion()).rejects.toBeInstanceOf(ApiError);
  });

  it('sends a client correlation id header', async () => {
    const fetchMock = mockFetchOk(versionPayload);
    global.fetch = fetchMock;
    const { api } = await import('./api/client');
    await api.getVersion();
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers['X-Request-ID']).toMatch(/^req_ui_[0-9a-f]{24}$/);
  });
});
