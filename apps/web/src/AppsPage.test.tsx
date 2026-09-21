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
    global: ['project.read', 'project.create', 'deployment.read', 'deployment.create', 'deployment.rollback'],
    scoped: [],
  },
};

const mfaEnrolled = { totp_enrolled: true, totp_enrollment_pending: false, recovery_codes_remaining: 8 };

const testProject = {
  id: 'p-1',
  slug: 'app-project',
  name: 'App Project',
  description: 'Test project description',
  state: 'active',
  created_at: '2026-09-20T00:00:00Z',
  updated_at: '2026-09-20T00:00:00Z',
};

const testApp = {
  id: 'app-1',
  project_id: 'p-1',
  server_id: 'srv-1',
  slug: 'api-service',
  name: 'API Service',
  runtime_type: 'node',
  state: 'active',
  git_repo_url: 'https://github.com/example/api.git',
  git_ref_default: 'main',
  build_program: 'npm',
  build_args: ['run', 'build'],
  start_program: 'node',
  start_args: ['dist/index.js'],
  working_dir: '',
  port: 3000,
  health_path: '/health',
  env_name: 'production',
  created_at: '2026-09-21T00:00:00Z',
  updated_at: '2026-09-21T00:00:00Z',
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

function mockAppsApi(overrides: Record<string, unknown> = {}) {
  const defaultRoutes: Record<string, unknown> = {
    'GET /api/v1/version': versionPayload,
    'GET /api/v1/auth/session': ownerSession,
    'GET /api/v1/auth/csrf': { csrf_token: 'csrf_test_token' },
    'GET /api/v1/auth/mfa': mfaEnrolled,
    'GET /api/v1/projects?state=active&limit=50': { projects: [testProject], total: 1, limit: 50, offset: 0, has_more: false },
    'GET /api/v1/projects?state=active': { projects: [testProject], total: 1, limit: 50, offset: 0, has_more: false },
    'GET /api/v1/projects': { projects: [testProject], total: 1, limit: 50, offset: 0, has_more: false },
    'GET /api/v1/projects/p-1/apps?limit=50': { apps: [testApp], total: 1, limit: 50, offset: 0, has_more: false },
    'GET /api/v1/projects/p-1/apps': { apps: [testApp], total: 1, limit: 50, offset: 0, has_more: false },
    'GET /api/v1/projects/p-1/apps/app-1/deployments?limit=10': { deployments: [], total: 0, limit: 10, offset: 0, has_more: false },
    'GET /api/v1/projects/p-1/apps/app-1/deployments': { deployments: [], total: 0, limit: 10, offset: 0, has_more: false },
    'GET /api/v1/projects/p-1/apps/app-1/releases': { releases: [] },
    'GET /api/v1/projects/p-1/apps/app-1/env': { env_vars: [] },
    'GET /api/v1/projects/p-1/apps/app-1/webhook-tokens': { webhook_tokens: [] },
    'GET /api/v1/servers': { servers: [], total: 0, limit: 50, offset: 0, has_more: false },
    ...overrides,
  };

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    const method = init?.method ?? 'GET';
    const key = `${method} ${path}`;

    if (key in defaultRoutes) return okResponse(defaultRoutes[key]);
    if (path in defaultRoutes) return okResponse(defaultRoutes[path]);

    return okResponse({});
  });

  global.fetch = fetchMock as unknown as typeof fetch;
  return fetchMock;
}

describe('Apps page', () => {
  beforeEach(() => {
    window.location.hash = '#/apps';
  });

  it('renders apps nav link and displays project picker', async () => {
    mockAppsApi();
    render(<App />);

    expect(await screen.findByRole('link', { name: 'Apps' })).toBeInTheDocument();
    expect(await screen.findByText('App Project (app-project)')).toBeInTheDocument();
  });

  it('displays app list after selecting project and opens app detail', async () => {
    mockAppsApi();
    render(<App />);

    // Wait for projects to load, then select the project in the dropdown
    await screen.findByRole('option', { name: /App Project/ });
    const select = screen.getByRole('combobox');
    await userEvent.selectOptions(select, 'p-1');

    // App should appear in the list
    expect(await screen.findByText('API Service')).toBeInTheDocument();

    // Click app to open detail view
    await userEvent.click(screen.getByText('API Service'));

    // Detail view tabs — "Deploy" tab is now "Deployments" to avoid collision with trigger button
    expect(await screen.findByRole('button', { name: 'Deployments' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Env Vars' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Webhooks' })).toBeInTheDocument();
  });

  it('enforces commit SHA validation: Deploy button is disabled until valid hex SHA is entered', async () => {
    mockAppsApi();
    render(<App />);

    await screen.findByRole('option', { name: /App Project/ });
    const select = screen.getByRole('combobox');
    await userEvent.selectOptions(select, 'p-1');

    await userEvent.click(await screen.findByText('API Service'));

    // "Deploy" trigger button is separate from the "Deployments" tab button
    const deployBtn = await screen.findByRole('button', { name: 'Deploy' });
    // Deploy button is initially disabled (empty commit SHA)
    expect(deployBtn).toBeDisabled();

    // Enter invalid SHA (too short: 5 chars)
    const shaInput = screen.getByPlaceholderText('abc1234');
    await userEvent.type(shaInput, '12345');
    expect(deployBtn).toBeDisabled();

    // Enter valid 7-char hex SHA
    await userEvent.type(shaInput, '67');
    await waitFor(() => expect(deployBtn).not.toBeDisabled());
  });
});
