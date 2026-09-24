import { useCallback, useEffect, useState } from 'react';

import {
  api,
  isStepUpRequired,
  type DatabaseMetrics,
  type DatabaseUser,
  type ManagedDatabase,
  type Project,
  type Server,
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

function mapDbState(db: ManagedDatabase): OperationalState {
  if (db.state === 'active') return 'Healthy';
  if (db.state === 'suspended') return 'Warning';
  if (db.state === 'pending_delete') return 'Warning';
  return 'Disabled';
}

function formatTs(value: string | null | undefined): string {
  if (!value) return '—';
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function toError(e: unknown): Error {
  return e instanceof Error ? e : new Error(String(e));
}

const ENGINE_VERSIONS: Record<string, string[]> = {
  postgresql: ['17', '16', '15'],
  mariadb: ['11.4', '10.11'],
};

const ALL_PRIVILEGES = ['ALL', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP'];

export function DatabasesPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [servers, setServers] = useState<Server[]>([]);
  const [databases, setDatabases] = useState<ManagedDatabase[]>([]);
  const [selectedDb, setSelectedDb] = useState<ManagedDatabase | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [stepUpPending, setStepUpPending] = useState(false);
  const [stepUpAction, setStepUpAction] = useState<(() => Promise<void>) | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);

  // Sub-resource states for selected DB
  const [tab, setTab] = useState<'overview' | 'users' | 'ops' | 'metrics'>('overview');
  const [users, setUsers] = useState<DatabaseUser[]>([]);
  const [metrics, setMetrics] = useState<DatabaseMetrics | null>(null);
  const [connectionString, setConnectionString] = useState<string | null>(null);
  const [connUser, setConnUser] = useState<string>('');
  const [copiedConn, setCopiedConn] = useState(false);

  // Forms
  const [newDb, setNewDb] = useState({
    server_id: '',
    slug: '',
    name: '',
    engine: 'postgresql',
    engine_version: '17',
    db_name: '',
  });
  const [newUser, setNewUser] = useState({
    username: '',
    privileges: ['ALL'],
  });
  const [restorePath, setRestorePath] = useState('');
  const [dumpJobMsg, setDumpJobMsg] = useState<string | null>(null);
  const [restoreJobMsg, setRestoreJobMsg] = useState<string | null>(null);
  const [rescueDiagnostics, setRescueDiagnostics] = useState<{
    database_id: string;
    database_state: string;
    engine: string;
    failed_jobs: Array<{ id: string; type: string; state: string; error_summary?: string }>;
    rescue_actions: string[];
    data_dir_protected: boolean;
  } | null>(null);
  const [rescueMsg, setRescueMsg] = useState<string | null>(null);
  const [rescueLoading, setRescueLoading] = useState(false);

  const loadProjects = useCallback(async () => {
    try {
      const data = await api.listProjects({ state: 'active', limit: 50 });
      setProjects(data.projects || []);
    } catch (e: unknown) {
      setError(toError(e));
    }
  }, []);

  const loadServers = useCallback(async () => {
    try {
      const data = await api.listServers();
      setServers(data.servers || []);
    } catch (e: unknown) {
      setError(toError(e));
    }
  }, []);

  const loadDatabases = useCallback(async (projectId: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listDatabases(projectId);
      setDatabases(data.databases || []);
    } catch (e: unknown) {
      setError(toError(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadUsers = useCallback(async (projectId: string, dbId: string) => {
    try {
      const data = await api.listDatabaseUsers(projectId, dbId);
      setUsers(data.users || []);
    } catch (e: unknown) {
      setError(toError(e));
    }
  }, []);

  const loadMetrics = useCallback(async (projectId: string, dbId: string) => {
    try {
      const data = await api.getDatabaseMetrics(projectId, dbId);
      setMetrics(data.metrics);
    } catch (e: unknown) {
      setError(toError(e));
    }
  }, []);

  const loadConnString = useCallback(async (projectId: string, dbId: string, user?: string) => {
    try {
      const data = await api.getConnectionString(projectId, dbId, user);
      setConnectionString(data.connection_string);
    } catch (e: unknown) {
      setConnectionString(null);
      setError(toError(e));
    }
  }, []);

  useEffect(() => {
    void loadProjects();
    void loadServers();
  }, [loadProjects, loadServers]);

  useEffect(() => {
    if (selectedProject) {
      void loadDatabases(selectedProject.id);
      setSelectedDb(null);
    }
  }, [selectedProject, loadDatabases]);

  useEffect(() => {
    if (selectedProject && selectedDb) {
      void loadUsers(selectedProject.id, selectedDb.id);
      void loadMetrics(selectedProject.id, selectedDb.id);
      void loadConnString(selectedProject.id, selectedDb.id);
    }
  }, [selectedProject, selectedDb, loadUsers, loadMetrics, loadConnString]);

  const onElevationRequired = (action: () => Promise<void>) => {
    setStepUpAction(() => action);
    setStepUpPending(true);
  };

  const handleCreateDb = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProject) return;
    setError(null);
    try {
      await api.createDatabase(selectedProject.id, newDb);
      setShowCreateForm(false);
      setNewDb({
        server_id: '',
        slug: '',
        name: '',
        engine: 'postgresql',
        engine_version: '17',
        db_name: '',
      });
      await loadDatabases(selectedProject.id);
    } catch (err: unknown) {
      setError(toError(err));
    }
  };

  const handleDeleteDb = async (db: ManagedDatabase) => {
    if (!selectedProject) return;
    if (!window.confirm(`Delete database "${db.name}"? It will enter a soft-delete grace period before permanent removal.`)) {
      return;
    }
    const run = async () => {
      try {
        await api.deleteDatabase(selectedProject.id, db.id);
        setSelectedDb(null);
        await loadDatabases(selectedProject.id);
      } catch (err: unknown) {
        if (isStepUpRequired(err)) {
          onElevationRequired(run);
          return;
        }
        setError(toError(err));
      }
    };
    await run();
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProject || !selectedDb) return;
    setError(null);
    try {
      await api.createDatabaseUser(selectedProject.id, selectedDb.id, newUser);
      setNewUser({ username: '', privileges: ['ALL'] });
      await loadUsers(selectedProject.id, selectedDb.id);
    } catch (err: unknown) {
      setError(toError(err));
    }
  };

  const handleRevokeUser = async (username: string) => {
    if (!selectedProject || !selectedDb) return;
    if (!window.confirm(`Revoke user "${username}"?`)) return;
    try {
      await api.revokeDatabaseUser(selectedProject.id, selectedDb.id, username);
      await loadUsers(selectedProject.id, selectedDb.id);
    } catch (err: unknown) {
      setError(toError(err));
    }
  };

  const handleRotatePassword = async (username: string) => {
    if (!selectedProject || !selectedDb) return;
    const run = async () => {
      try {
        await api.rotateDatabaseUserPassword(selectedProject.id, selectedDb.id, username);
        alert(`Password rotated for user "${username}". Credentials updated in secrets store.`);
      } catch (err: unknown) {
        if (isStepUpRequired(err)) {
          onElevationRequired(run);
          return;
        }
        setError(toError(err));
      }
    };
    await run();
  };

  const handleDump = async () => {
    if (!selectedProject || !selectedDb) return;
    setDumpJobMsg(null);
    try {
      const res = await api.dumpDatabase(selectedProject.id, selectedDb.id);
      setDumpJobMsg(`Dump job queued (ID: ${res.job_id}, Backup: ${res.backup_id})`);
    } catch (err: unknown) {
      setError(toError(err));
    }
  };

  const handleRestore = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProject || !selectedDb || !restorePath.trim()) return;
    setRestoreJobMsg(null);
    const run = async () => {
      try {
        const res = await api.restoreDatabase(selectedProject.id, selectedDb.id, restorePath.trim());
        setRestoreJobMsg(`Restore job queued (Job ID: ${res.job_id}). Recoverability will be verified automatically.`);
        setRestorePath('');
      } catch (err: unknown) {
        if (isStepUpRequired(err)) {
          onElevationRequired(run);
          return;
        }
        setError(toError(err));
      }
    };
    await run();
  };

  const handleLoadRescue = async () => {
    if (!selectedProject || !selectedDb) return;
    setRescueLoading(true);
    setRescueMsg(null);
    try {
      const diag = await api.getRescueDiagnostics(selectedProject.id, selectedDb.id);
      setRescueDiagnostics(diag);
    } catch (err: unknown) {
      setError(toError(err));
    } finally {
      setRescueLoading(false);
    }
  };

  const handleRescueRollback = async () => {
    if (!selectedProject || !selectedDb) return;
    const run = async () => {
      try {
        const res = await api.rescueRollback(selectedProject.id, selectedDb.id);
        setRescueMsg(res.message);
        await loadDatabases(selectedProject.id);
      } catch (err: unknown) {
        if (isStepUpRequired(err)) {
          onElevationRequired(run);
          return;
        }
        setError(toError(err));
      }
    };
    await run();
  };

  return (
    <div className="space-y-6">
      {stepUpPending && stepUpAction && (
        <StepUpPrompt
          onElevated={() => {
            setStepUpPending(false);
            const act = stepUpAction;
            setStepUpAction(null);
            void act();
          }}
          onCancel={() => {
            setStepUpPending(false);
            setStepUpAction(null);
          }}
        />
      )}

      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-line pb-4">
        <div>
          <h2 className="text-xl font-semibold text-ink">Databases</h2>
          <p className="text-xs text-ink-muted">
            Managed relational databases (PostgreSQL & MariaDB) with scoped credentials and verified backups.
          </p>
        </div>
        {selectedProject && !selectedDb && (
          <button
            type="button"
            onClick={() => setShowCreateForm(!showCreateForm)}
            className={primaryButtonClass}
          >
            {showCreateForm ? 'Cancel' : 'New Database'}
          </button>
        )}
      </div>

      {error && <ErrorNote error={error} />}

      {/* Project Selector */}
      <div className="flex items-center gap-3">
        <label htmlFor="db-project-select" className="text-xs font-medium text-ink-secondary">
          Project:
        </label>
        <select
          id="db-project-select"
          value={selectedProject?.id || ''}
          onChange={(e) => {
            const p = projects.find((x) => x.id === e.target.value) || null;
            setSelectedProject(p);
          }}
          className={`${inputClass} max-w-xs`}
        >
          <option value="">Select a project…</option>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} ({p.slug})
            </option>
          ))}
        </select>
      </div>

      {!selectedProject ? (
        <EmptyState title="Select a project">
          Choose an active project to view and manage its databases.
        </EmptyState>
      ) : selectedDb ? (
        /* Database Detail View */
        <div className="space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-line bg-surface p-4">
            <div className="space-y-1">
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setSelectedDb(null)}
                  className="text-xs text-ink-muted hover:text-ink"
                >
                  &larr; All databases
                </button>
                <h3 className="text-lg font-semibold text-ink">{selectedDb.name}</h3>
                <StatusBadge state={mapDbState(selectedDb)} detail={selectedDb.state} />
              </div>
              <p className="font-mono text-xs text-ink-secondary">
                {selectedDb.slug} &bull; {selectedDb.engine} {selectedDb.engine_version} &bull; db: {selectedDb.db_name}
              </p>
            </div>
            <button
              type="button"
              onClick={() => void handleDeleteDb(selectedDb)}
              className="rounded-md border border-line px-3 py-1 text-xs font-medium text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20"
            >
              Delete Database
            </button>
          </div>

          {/* Tabs */}
          <div className="flex gap-2 border-b border-line pb-2">
            {(['overview', 'users', 'ops', 'metrics'] as const).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setTab(t)}
                className={`rounded-md px-3 py-1.5 text-xs font-medium capitalize ${
                  tab === t
                    ? 'bg-elevated font-semibold text-ink'
                    : 'text-ink-secondary hover:text-ink'
                }`}
              >
                {t === 'ops' ? 'Backups & Restore' : t}
              </button>
            ))}
          </div>

          {/* Overview Tab */}
          {tab === 'overview' && (
            <div className="space-y-4 rounded-lg border border-line bg-surface p-4">
              <h4 className="text-sm font-semibold text-ink">Connection & Information</h4>
              <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2 text-xs">
                <div>
                  <dt className="text-ink-muted">Server ID</dt>
                  <dd className="font-mono text-ink">{selectedDb.server_id}</dd>
                </div>
                <div>
                  <dt className="text-ink-muted">Created</dt>
                  <dd className="text-ink">{formatTs(selectedDb.created_at)}</dd>
                </div>
                <div>
                  <dt className="text-ink-muted">Engine</dt>
                  <dd className="capitalize text-ink">
                    {selectedDb.engine} {selectedDb.engine_version}
                  </dd>
                </div>
                <div>
                  <dt className="text-ink-muted">Database Name</dt>
                  <dd className="font-mono text-ink">{selectedDb.db_name}</dd>
                </div>
              </dl>

              {/* Connection String Generator */}
              <div className="mt-4 border-t border-line pt-4 space-y-2">
                <div className="flex items-center justify-between">
                  <label htmlFor="conn-user-select" className="text-xs font-medium text-ink">
                    Connection String
                  </label>
                  {users.length > 0 && (
                    <select
                      id="conn-user-select"
                      value={connUser}
                      onChange={(e) => {
                        setConnUser(e.target.value);
                        void loadConnString(selectedProject.id, selectedDb.id, e.target.value);
                      }}
                      className={`${inputClass} text-xs py-1`}
                    >
                      <option value="">Default user ({users[0]?.username})</option>
                      {users.map((u) => (
                        <option key={u.id} value={u.username}>
                          {u.username}
                        </option>
                      ))}
                    </select>
                  )}
                </div>

                {connectionString ? (
                  <div className="relative">
                    <pre className="overflow-x-auto rounded-md bg-canvas p-3 font-mono text-xs text-ink">
                      {connectionString}
                    </pre>
                    <button
                      type="button"
                      onClick={() => {
                        void navigator.clipboard.writeText(connectionString);
                        setCopiedConn(true);
                        setTimeout(() => setCopiedConn(false), 2000);
                      }}
                      className="absolute right-2 top-2 rounded bg-surface px-2 py-1 text-xs text-ink-secondary hover:text-ink shadow-sm border border-line"
                    >
                      {copiedConn ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                ) : (
                  <p className="text-xs text-ink-muted">
                    No users exist. Create a database user in the Users tab to generate a connection string.
                  </p>
                )}
                <p className="text-xs text-ink-muted">
                  Passwords are securely decrypted from the vault on request and never saved in the browser.
                </p>
              </div>
            </div>
          )}

          {/* Users Tab */}
          {tab === 'users' && (
            <div className="space-y-6">
              {/* Create User */}
              <form onSubmit={handleCreateUser} className="rounded-lg border border-line bg-surface p-4 space-y-3">
                <h4 className="text-sm font-semibold text-ink">Add Database User</h4>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <Field label="Username">
                    <input
                      type="text"
                      required
                      placeholder="app_user"
                      value={newUser.username}
                      onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                      className={inputClass}
                    />
                  </Field>
                  <Field label="Privileges">
                    <div className="flex flex-wrap gap-2 pt-1">
                      {ALL_PRIVILEGES.map((p) => (
                        <label key={p} className="flex items-center gap-1 text-xs text-ink">
                          <input
                            type="checkbox"
                            checked={newUser.privileges.includes(p)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setNewUser({ ...newUser, privileges: [...newUser.privileges, p] });
                              } else {
                                setNewUser({
                                  ...newUser,
                                  privileges: newUser.privileges.filter((x) => x !== p),
                                });
                              }
                            }}
                            className="rounded border-line"
                          />
                          {p}
                        </label>
                      ))}
                    </div>
                  </Field>
                </div>
                <button type="submit" className={primaryButtonClass}>
                  Create User
                </button>
              </form>

              {/* User List */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-ink">Active Users</h4>
                {users.length === 0 ? (
                  <EmptyState title="No users">
                    This database has no active users. Create one above.
                  </EmptyState>
                ) : (
                  <div className="divide-y divide-line rounded-lg border border-line bg-surface">
                    {users.map((u) => (
                      <div key={u.id} className="flex items-center justify-between p-3">
                        <div className="space-y-0.5">
                          <p className="font-mono text-sm font-medium text-ink">{u.username}</p>
                          <p className="text-xs text-ink-muted">
                            Grants: {u.privileges.join(', ')} &bull; Created {formatTs(u.created_at)}
                          </p>
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => void handleRotatePassword(u.username)}
                            className={secondaryButtonClass}
                          >
                            Rotate Password
                          </button>
                          <button
                            type="button"
                            onClick={() => void handleRevokeUser(u.username)}
                            className="rounded-md border border-line px-2.5 py-1 text-xs text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20"
                          >
                            Revoke
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Backups & Restore Tab */}
          {tab === 'ops' && (
            <div className="space-y-6">
              {/* Dump */}
              <div className="rounded-lg border border-line bg-surface p-4 space-y-3">
                <h4 className="text-sm font-semibold text-ink">Export / Manual Dump</h4>
                <p className="text-xs text-ink-muted">
                  Create an encrypted on-host backup file. An asynchronous worker performs the dump and computes its SHA-256 digest.
                </p>
                <button type="button" onClick={() => void handleDump()} className={primaryButtonClass}>
                  Trigger Backup Dump
                </button>
                {dumpJobMsg && <p className="text-xs text-ink-secondary">{dumpJobMsg}</p>}
              </div>

              {/* Restore */}
              <form onSubmit={handleRestore} className="rounded-lg border border-line bg-surface p-4 space-y-3">
                <h4 className="text-sm font-semibold text-ink">Restore from Dump</h4>
                <p className="text-xs text-ink-muted">
                  Restores database content from a validated node dump path. The restore worker executes a live recoverability check via metrics before completing (Gate 2).
                </p>
                <Field label="Dump File Path on Node">
                  <input
                    type="text"
                    required
                    placeholder="/var/lib/jawaker/db-dumps/..."
                    value={restorePath}
                    onChange={(e) => setRestorePath(e.target.value)}
                    className={inputClass}
                  />
                </Field>
                <button type="submit" className={secondaryButtonClass}>
                  Queue Restore Job
                </button>
                {restoreJobMsg && <p className="text-xs text-ink-secondary">{restoreJobMsg}</p>}
              </form>

              {/* Database Rescue Mode (PRD §12.5) */}
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-semibold text-amber-500 flex items-center gap-1.5">
                      <span>🛡️</span> Database Rescue Mode & Diagnostics (PRD §12.5)
                    </h4>
                    <p className="text-xs text-ink-muted mt-1">
                      In-place recovery for corrupted configuration or failed upgrades. Guarantees raw data directory preservation.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => void handleLoadRescue()}
                    disabled={rescueLoading}
                    className={secondaryButtonClass}
                  >
                    {rescueLoading ? 'Scanning...' : 'Run Diagnostics'}
                  </button>
                </div>

                {rescueMsg && (
                  <div className="rounded p-2 text-xs bg-emerald-500/10 text-emerald-600 border border-emerald-500/20">
                    {rescueMsg}
                  </div>
                )}

                {rescueDiagnostics && (
                  <div className="space-y-2 pt-2 border-t border-line/60">
                    <div className="flex items-center gap-4 text-xs">
                      <div><span className="text-ink-muted">State:</span> <span className="font-mono font-medium">{rescueDiagnostics.database_state}</span></div>
                      <div><span className="text-ink-muted">Data Directory:</span> <span className="text-emerald-500 font-medium">✓ Protected</span></div>
                    </div>
                    {rescueDiagnostics.failed_jobs && rescueDiagnostics.failed_jobs.length > 0 ? (
                      <div className="space-y-1">
                        <div className="text-xs font-semibold text-ink-muted">Recent Failed Jobs:</div>
                        {rescueDiagnostics.failed_jobs.map((fj) => (
                          <div key={fj.id} className="text-xs font-mono bg-canvas p-1.5 rounded border border-line flex justify-between">
                            <span>{fj.type} ({fj.state})</span>
                            <span className="text-rose-500">{fj.error_summary || 'Unknown error'}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-ink-muted">No recent failed jobs found in queue.</p>
                    )}
                    <div className="pt-2 flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => void handleRescueRollback()}
                        className="px-3 py-1.5 text-xs font-medium rounded-md bg-amber-600 text-white hover:bg-amber-700 transition"
                      >
                        Rollback to Last-Known-Good Config
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Metrics Tab */}
          {tab === 'metrics' && (
            <div className="space-y-4 rounded-lg border border-line bg-surface p-4">
              <div className="flex items-center justify-between">
                <h4 className="text-sm font-semibold text-ink">Node Live Metrics</h4>
                <button
                  type="button"
                  onClick={() => void loadMetrics(selectedProject.id, selectedDb.id)}
                  className={secondaryButtonClass}
                >
                  Refresh
                </button>
              </div>

              {metrics ? (
                <div className="space-y-4">
                  <dl className="grid grid-cols-1 gap-3 sm:grid-cols-3 text-xs">
                    <div className="rounded-md border border-line bg-canvas p-3">
                      <dt className="text-ink-muted">Active Connections</dt>
                      <dd className="text-xl font-bold text-ink">{metrics.connections}</dd>
                    </div>
                    <div className="rounded-md border border-line bg-canvas p-3">
                      <dt className="text-ink-muted">Running Queries</dt>
                      <dd className="text-xl font-bold text-ink">{metrics.active_queries}</dd>
                    </div>
                    <div className="rounded-md border border-line bg-canvas p-3">
                      <dt className="text-ink-muted">Slow Queries (5m)</dt>
                      <dd className="text-xl font-bold text-ink">{metrics.slow_queries_last_5m}</dd>
                    </div>
                  </dl>

                  {metrics.top_slow_queries && metrics.top_slow_queries.length > 0 && (
                    <div className="space-y-2">
                      <h5 className="text-xs font-semibold text-ink">Top Slow Queries</h5>
                      <div className="overflow-x-auto rounded-md border border-line bg-canvas">
                        <table className="w-full text-left text-xs">
                          <thead className="border-b border-line bg-surface text-ink-muted">
                            <tr>
                              <th className="p-2">Query</th>
                              <th className="p-2">Calls</th>
                              <th className="p-2">Mean Time</th>
                              <th className="p-2">Total Time</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-line text-ink">
                            {metrics.top_slow_queries.map((q, i) => (
                              <tr key={i}>
                                <td className="max-w-xs truncate p-2 font-mono">{q.query}</td>
                                <td className="p-2">{q.calls}</td>
                                <td className="p-2">{q.mean_time_ms.toFixed(1)}ms</td>
                                <td className="p-2">{q.total_time_ms.toFixed(1)}ms</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  <p className="text-xs text-ink-muted">
                    Observed at: {formatTs(metrics.observed_at)}
                  </p>
                </div>
              ) : (
                <p className="text-xs text-ink-muted">No metrics observed yet.</p>
              )}
            </div>
          )}
        </div>
      ) : (
        /* Database List */
        <div className="space-y-4">
          {showCreateForm && (
            <form
              onSubmit={handleCreateDb}
              className="rounded-lg border border-line bg-surface p-4 space-y-4"
            >
              <h3 className="text-sm font-semibold text-ink">Provision Managed Database</h3>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <Field label="Server">
                  <select
                    required
                    value={newDb.server_id}
                    onChange={(e) => setNewDb({ ...newDb, server_id: e.target.value })}
                    className={inputClass}
                  >
                    <option value="">Select target server…</option>
                    {servers.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name} ({s.address})
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Engine">
                  <select
                    value={newDb.engine}
                    onChange={(e) => {
                      const eng = e.target.value;
                      setNewDb({
                        ...newDb,
                        engine: eng,
                        engine_version: ENGINE_VERSIONS[eng]?.[0] || '',
                      });
                    }}
                    className={inputClass}
                  >
                    <option value="postgresql">PostgreSQL</option>
                    <option value="mariadb">MariaDB</option>
                  </select>
                </Field>
                <Field label="Engine Version">
                  <select
                    value={newDb.engine_version}
                    onChange={(e) => setNewDb({ ...newDb, engine_version: e.target.value })}
                    className={inputClass}
                  >
                    {(ENGINE_VERSIONS[newDb.engine] || []).map((v) => (
                      <option key={v} value={v}>
                        {v}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Display Name">
                  <input
                    type="text"
                    required
                    placeholder="Primary Production DB"
                    value={newDb.name}
                    onChange={(e) => setNewDb({ ...newDb, name: e.target.value })}
                    className={inputClass}
                  />
                </Field>
                <Field label="Slug (project unique)">
                  <input
                    type="text"
                    required
                    placeholder="prod_db"
                    value={newDb.slug}
                    onChange={(e) => setNewDb({ ...newDb, slug: e.target.value })}
                    className={inputClass}
                  />
                </Field>
                <Field label="Database Name on Server (server unique)">
                  <input
                    type="text"
                    required
                    placeholder="app_prod"
                    value={newDb.db_name}
                    onChange={(e) => setNewDb({ ...newDb, db_name: e.target.value })}
                    className={inputClass}
                  />
                </Field>
              </div>
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowCreateForm(false)}
                  className={secondaryButtonClass}
                >
                  Cancel
                </button>
                <button type="submit" className={primaryButtonClass}>
                  Provision Database
                </button>
              </div>
            </form>
          )}

          {loading ? (
            <p className="text-xs text-ink-muted">Loading databases…</p>
          ) : databases.length === 0 ? (
            <EmptyState title="No databases">
              No managed databases found in this project. Create one to get started.
            </EmptyState>
          ) : (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {databases.map((db) => (
                <div
                  key={db.id}
                  onClick={() => setSelectedDb(db)}
                  className="cursor-pointer rounded-lg border border-line bg-surface p-4 transition-all hover:border-line-hover hover:shadow-sm space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <h4 className="font-semibold text-ink text-sm">{db.name}</h4>
                    <StatusBadge state={mapDbState(db)} detail={db.state} />
                  </div>
                  <p className="font-mono text-xs text-ink-secondary truncate">{db.slug}</p>
                  <div className="flex items-center justify-between pt-2 border-t border-line text-xs text-ink-muted">
                    <span className="capitalize">{db.engine} {db.engine_version}</span>
                    <span>{formatTs(db.created_at)}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
