import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import App from './App';

const versionPayload = { version: '0.1.0-dev', commit: 'abc1234', build_time: '2026-09-19T00:00:00Z' };

const ownerSession = {
  user: { id: 'u-1', email: 'owner@example.test', display_name: 'Owner', is_owner: true },
  session_id: 's-1',
  elevated: false,
  permissions: {
    global: ['project.read', 'project.create', 'site.read', 'site.create', 'site.manage', 'site.delete', 'jobs.read'],
    scoped: [],
  },
};

const mfaEnrolled = { totp_enrolled: true, totp_enrollment_pending: false, recovery_codes_remaining: 8 };

const testProject = {
  id: 'p-1',
  slug: 'test-project',
  name: 'Test Project',
  description: 'Test project description',
  state: 'active',
  created_at: '2026-09-20T00:00:00Z',
  updated_at: '2026-09-20T00:00:00Z',
};

const testSite = {
  id: 's-1',
  project_id: 'p-1',
  server_id: 'srv-1',
  slug: 'my-site',
  name: 'My Site',
  mode: 'static',
  state: 'active',
  doc_root: '/var/www/html',
  upstream: '',
  php_unit: '',
  applied_revision_id: 'rev-1',
  created_at: '2026-09-20T00:00:00Z',
  updated_at: '2026-09-20T00:00:00Z',
};

function okResponse(body: unknown, status = 200) {
  return {
    ok: true,
    status,
    headers: new Headers({ 'X-Request-ID': 'req_test' }),
    json: async () => body,
    clone() { return this; },
  };
}

function mockSitesApi(overrides: Record<string, unknown> = {}) {
  const defaultRoutes: Record<string, unknown> = {
    'GET /api/v1/version': versionPayload,
    'GET /api/v1/auth/session': ownerSession,
    'GET /api/v1/auth/csrf': { csrf_token: 'csrf_test_token' },
    'GET /api/v1/auth/mfa': mfaEnrolled,
    'GET /api/v1/projects?state=active': { projects: [testProject], total: 1, limit: 50, offset: 0, has_more: false },
    'GET /api/v1/projects': { projects: [testProject], total: 1, limit: 50, offset: 0, has_more: false },
    'GET /api/v1/projects/p-1/sites': { sites: [testSite], total: 1, limit: 50, offset: 0, has_more: false },
    'GET /api/v1/servers': { servers: [], total: 0, limit: 50, offset: 0, has_more: false },
    ...overrides,
  };

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    const method = init?.method ?? 'GET';
    const key = `${method} ${path}`;

    if (key in defaultRoutes) {
      return okResponse(defaultRoutes[key]);
    }
    if (path in defaultRoutes) {
      return okResponse(defaultRoutes[path]);
    }

    return okResponse({});
  });

  global.fetch = fetchMock as unknown as typeof fetch;
  return fetchMock;
}

describe('Sites page', () => {
  beforeEach(() => {
    window.location.hash = '#/sites';
  });

  it('renders projects and sites list', async () => {
    mockSitesApi();
    render(<App />);

    // Expect navigation entry
    expect(await screen.findByRole('link', { name: 'Sites' })).toBeInTheDocument();

    // Expect project button
    const projectBtn = await screen.findByRole('button', { name: 'test-project' });
    expect(projectBtn).toBeInTheDocument();

    // Click project to see sites
    await userEvent.click(projectBtn);

    // Expect site row
    expect(await screen.findByText('my-site')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Manage' })).toBeInTheDocument();
  });

  it('enforces validate-before-apply gate: Apply is disabled until candidate validates', async () => {
    mockSitesApi({
      'POST /api/v1/projects/p-1/sites/s-1/validate': {
        valid: true,
        tool: 'nginx',
        tool_version: '1.24.0',
        output: 'syntax is ok',
        truncated: false,
        staged: '/tmp/test.conf',
        observed_at: '2026-09-20T01:00:00Z',
        request_id: 'req_v1',
      },
    });
    render(<App />);

    // Navigate to site manage
    const projectBtn = await screen.findByRole('button', { name: 'test-project' });
    await userEvent.click(projectBtn);

    const manageBtn = await screen.findByRole('button', { name: 'Manage' });
    await userEvent.click(manageBtn);

    // Find the Config tab and buttons
    const validateBtn = await screen.findByRole('button', { name: 'Validate' });
    const applyBtn = screen.getByRole('button', { name: 'Apply' });

    // GATE 1: Apply must be disabled before validation
    expect(applyBtn).toBeDisabled();

    // Run validate
    await userEvent.click(validateBtn);

    // Verdict shown
    expect(await screen.findByText(/Valid — nginx 1.24.0/)).toBeInTheDocument();

    // GATE 2: Apply becomes enabled after passing validation
    expect(applyBtn).toBeEnabled();

    // GATE 3: Editing candidate invalidates verdict and disables Apply
    const textarea = screen.getByLabelText('Nginx configuration candidate');
    await userEvent.type(textarea, '# another edit\n');

    await waitFor(() => {
      expect(applyBtn).toBeDisabled();
    });
    expect(screen.getByText(/Edit invalidated the verdict/)).toBeInTheDocument();
  });

  it('polls job progress after apply until terminal', async () => {
    let pollCount = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const method = init?.method ?? 'GET';

      if (path === '/api/v1/version') return okResponse(versionPayload);
      if (path === '/api/v1/auth/session') return okResponse(ownerSession);
      if (path === '/api/v1/auth/csrf') return okResponse({ csrf_token: 'csrf_1' });
      if (path === '/api/v1/auth/mfa') return okResponse(mfaEnrolled);
      if (path.startsWith('/api/v1/projects?')) return okResponse({ projects: [testProject], total: 1, limit: 50, offset: 0, has_more: false });
      if (path === '/api/v1/projects/p-1/sites') return okResponse({ sites: [testSite], total: 1, limit: 50, offset: 0, has_more: false });
      if (path.includes('/validate')) {
        return okResponse({
          valid: true,
          tool: 'nginx',
          tool_version: '1.24.0',
          output: 'syntax ok',
          truncated: false,
          staged: '/tmp/test.conf',
          observed_at: '2026-09-20T01:00:00Z',
          request_id: 'req_v1',
        });
      }
      if (method === 'POST' && path.includes('/apply')) {
        return okResponse({
          revision_id: 'rev-2',
          job: { id: 'job-apply-1', state: 'queued' },
          request_id: 'req_a1',
        }, 202);
      }
      if (path === '/api/v1/jobs/job-apply-1') {
        pollCount++;
        const state = pollCount >= 2 ? 'succeeded' : 'running';
        return okResponse({
          job: {
            id: 'job-apply-1',
            type: 'site.apply',
            server_id: 'srv-1',
            project_id: 'p-1',
            state,
            priority: 0,
            attempt_count: 1,
            max_attempts: 1,
            error_code: '',
            error_summary: '',
            created_at: '2026-09-20T01:00:00Z',
          },
          steps: [
            { index: 0, name: 'validate', state: 'succeeded', output: null, error_code: '', error_summary: '', attempt: 1 },
            { index: 1, name: 'apply', state, output: null, error_code: '', error_summary: '', attempt: 1 },
          ],
          request_id: 'req_j1',
        });
      }
      return okResponse({});
    });

    global.fetch = fetchMock as unknown as typeof fetch;
    render(<App />);

    await userEvent.click(await screen.findByRole('button', { name: 'test-project' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Manage' }));

    // Validate first
    await userEvent.click(await screen.findByRole('button', { name: 'Validate' }));
    const applyBtn = await screen.findByRole('button', { name: 'Apply' });
    await waitFor(() => expect(applyBtn).toBeEnabled());

    // Click Apply
    await userEvent.click(applyBtn);

    // Job progress appears
    expect(await screen.findByText(/Apply job —/)).toBeInTheDocument();
    expect(await screen.findByText('validate')).toBeInTheDocument();
  });

  it('fetches and displays site logs on demand', async () => {
    mockSitesApi({
      'GET /api/v1/projects/p-1/sites/s-1/logs?type=access&lines=100': {
        site_id: 's-1',
        log_type: 'access',
        lines: [
          '192.168.1.1 - - [20/Sep/2026:01:00:00 +0000] "GET / HTTP/1.1" 200 612',
          '192.168.1.2 - - [20/Sep/2026:01:00:01 +0000] "GET /about HTTP/1.1" 200 450',
        ],
        truncated: false,
        observed_at: '2026-09-20T01:00:02Z',
        request_id: 'req_logs',
      },
    });
    render(<App />);

    await userEvent.click(await screen.findByRole('button', { name: 'test-project' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Manage' }));

    // Switch to Logs tab
    const logsTab = screen.getByRole('tab', { name: 'logs' });
    await userEvent.click(logsTab);

    expect(screen.getByText(/Logs are read on-demand/)).toBeInTheDocument();

    // Fetch logs
    const fetchBtn = screen.getByRole('button', { name: 'Fetch logs' });
    await userEvent.click(fetchBtn);

    // Logs rendered in pre
    expect(await screen.findByText(/192\.168\.1\.1/)).toBeInTheDocument();
    expect(screen.getByText(/2 lines/)).toBeInTheDocument();
  });
});
