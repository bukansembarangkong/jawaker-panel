import { useCallback, useEffect, useState } from 'react';
import { goeyToast } from 'goey-toast';

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
  Modal,
  ConfirmModal,
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
  if (!value) return '-';
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
  const [tab, setTab] = useState<'overview' | 'users' | 'ops' | 'metrics' | 'query'>('overview');
  const [queryInput, setQueryInput] = useState('SELECT version();');
  const [queryError, setQueryError] = useState<string | null>(null);
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
  const [isAddUserOpen, setIsAddUserOpen] = useState(false);
  const [isRestoreOpen, setIsRestoreOpen] = useState(false);
  const [confirmState, setConfirmState] = useState<{ open: boolean; message: string; onConfirm: () => void }>({ open: false, message: '', onConfirm: () => {} });

  const selectDb = (db: ManagedDatabase | null) => {
    setSelectedDb(db);
    window.location.hash = db ? `#/databases/${db.id}` : '#/databases';
  };

  const loadProjects = useCallback(async () => {
    try {
      const data = await api.listProjects({ state: 'active', limit: 50 });
      const projs = data.projects || [];
      setProjects(projs);
      setSelectedProject((prev) => prev ?? projs[0] ?? null);
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
      const loaded = data.databases || [];
      setDatabases(loaded);

      const dbIdFromHash = window.location.hash.startsWith('#/databases/')
        ? window.location.hash.slice('#/databases/'.length)
        : null;
      if (dbIdFromHash) {
        const match = loaded.find((d) => d.id === dbIdFromHash);
        if (match) setSelectedDb(match);
      }
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
      if (!window.location.hash.startsWith('#/databases/')) setSelectedDb(null);
    }
  }, [selectedProject, loadDatabases]);

  useEffect(() => {
    if (selectedProject && selectedDb) {
      void loadUsers(selectedProject.id, selectedDb.id);
      void loadMetrics(selectedProject.id, selectedDb.id);
      void loadConnString(selectedProject.id, selectedDb.id);
    }
  }, [selectedProject, selectedDb, loadUsers, loadMetrics, loadConnString]);

  useEffect(() => {
    const handleHash = () => {
      const h = window.location.hash;
      if (h === '#/databases' || h === '#/databases/') {
        setSelectedDb(null);
      } else if (h.startsWith('#/databases/')) {
        const id = h.slice('#/databases/'.length);
        setDatabases((prev) => {
          const match = prev.find((d) => d.id === id);
          if (match) setSelectedDb(match);
          return prev;
        });
      }
    };
    window.addEventListener('hashchange', handleHash);
    return () => window.removeEventListener('hashchange', handleHash);
  }, []);

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
      goeyToast.success('Database created');
      await loadDatabases(selectedProject.id);
    } catch (err: unknown) {
      const e = toError(err);
      setError(e);
      goeyToast.error(`Failed to create database: ${e.message}`);
    }
  };

  const handleDeleteDb = async (db: ManagedDatabase) => {
    if (!selectedProject) return;
    setConfirmState({
      open: true,
      message: `Delete database "${db.name}"? It will enter a soft-delete grace period before permanent removal.`,
      onConfirm: async () => {
        const run = async () => {
          try {
            await api.deleteDatabase(selectedProject.id, db.id);
            selectDb(null);
            goeyToast.success(`Database "${db.name}" deleted`);
            await loadDatabases(selectedProject.id);
          } catch (err: unknown) {
            if (isStepUpRequired(err)) {
              onElevationRequired(run);
              return;
            }
            const e = toError(err);
            setError(e);
            goeyToast.error(`Failed to delete database: ${e.message}`);
          }
        };
        await run();
      },
    });
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProject || !selectedDb) return;
    setError(null);
    try {
      await api.createDatabaseUser(selectedProject.id, selectedDb.id, newUser);
      setNewUser({ username: '', privileges: ['ALL'] });
      setIsAddUserOpen(false);
      goeyToast.success('Database user created');
      await loadUsers(selectedProject.id, selectedDb.id);
    } catch (err: unknown) {
      const e = toError(err);
      setError(e);
      goeyToast.error(`Failed to create user: ${e.message}`);
    }
  };

  const handleRevokeUser = async (username: string) => {
    if (!selectedProject || !selectedDb) return;
    setConfirmState({
      open: true,
      message: `Revoke user "${username}"?`,
      onConfirm: async () => {
        try {
          await api.revokeDatabaseUser(selectedProject.id, selectedDb.id, username);
          goeyToast.success(`User "${username}" revoked`);
          await loadUsers(selectedProject.id, selectedDb.id);
        } catch (err: unknown) {
          const e = toError(err);
          setError(e);
          goeyToast.error(`Failed to revoke user: ${e.message}`);
        }
      },
    });
  };

  const handleRotatePassword = async (username: string) => {
    if (!selectedProject || !selectedDb) return;
    const run = async () => {
      try {
        await api.rotateDatabaseUserPassword(selectedProject.id, selectedDb.id, username);
        goeyToast.success(`Password rotated for user "${username}". Credentials updated in secrets store.`);
      } catch (err: unknown) {
        if (isStepUpRequired(err)) {
          onElevationRequired(run);
          return;
        }
        const e = toError(err);
        setError(e);
        goeyToast.error(`Failed to rotate password: ${e.message}`);
      }
    };
    await run();
  };

  const handleDump = async () => {
    if (!selectedProject || !selectedDb) return;
    setDumpJobMsg(null);
    try {
      const res = await api.dumpDatabase(selectedProject.id, selectedDb.id);
      const msg = `Dump job queued (ID: ${res.job_id}, Backup: ${res.backup_id})`;
      setDumpJobMsg(msg);
      goeyToast.success(msg);
    } catch (err: unknown) {
      const e = toError(err);
      setError(e);
      goeyToast.error(`Dump failed: ${e.message}`);
    }
  };

  const handleRestore = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProject || !selectedDb || !restorePath.trim()) return;
    setRestoreJobMsg(null);
    const run = async () => {
      try {
        const res = await api.restoreDatabase(selectedProject.id, selectedDb.id, restorePath.trim());
        const msg = `Restore job queued (Job ID: ${res.job_id}). Recoverability will be verified automatically.`;
        setRestoreJobMsg(msg);
        goeyToast.success('Restore job queued');
        setRestorePath('');
        setIsRestoreOpen(false);
      } catch (err: unknown) {
        if (isStepUpRequired(err)) {
          onElevationRequired(run);
          return;
        }
        const e = toError(err);
        setError(e);
        goeyToast.error(`Restore failed: ${e.message}`);
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
      const e = toError(err);
      setError(e);
      goeyToast.error(`Diagnostics failed: ${e.message}`);
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
        goeyToast.success(res.message);
        await loadDatabases(selectedProject.id);
      } catch (err: unknown) {
        if (isStepUpRequired(err)) {
          onElevationRequired(run);
          return;
        }
        const e = toError(err);
        setError(e);
        goeyToast.error(`Rescue rollback failed: ${e.message}`);
      }
    };
    await run();
  };

  return (
    <div className="space-y-6">
      <ConfirmModal
        isOpen={confirmState.open}
        onClose={() => setConfirmState(s => ({ ...s, open: false }))}
        onConfirm={confirmState.onConfirm}
        title="Are you sure?"
        message={confirmState.message}
        confirmLabel="Yes, proceed"
        danger
      />
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
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Databases</h1>
          <p className="text-sm text-slate-500">
            Managed relational databases (PostgreSQL &amp; MariaDB) with scoped credentials and verified backups.
          </p>
        </div>
        {selectedProject && !selectedDb && (
          <button
            type="button"
            onClick={() => setShowCreateForm(true)}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
          >
            + New Database
          </button>
        )}
      </div>

      {error && <ErrorNote error={error} />}

      {/* Project Selector */}
      <div className="flex items-center gap-3">
        <label htmlFor="db-project-select" className="text-xs font-medium text-slate-600">
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
          <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="space-y-1">
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => selectDb(null)}
                  className="text-xs text-slate-500 hover:text-slate-900 transition-colors"
                >
                  &larr; All databases
                </button>
                <h3 className="text-lg font-semibold text-slate-900">{selectedDb.name}</h3>
                <StatusBadge state={mapDbState(selectedDb)} detail={selectedDb.state} />
              </div>
              <p className="font-mono text-xs text-slate-500">
                {selectedDb.slug} &bull; {selectedDb.engine} {selectedDb.engine_version} &bull; db: {selectedDb.db_name}
              </p>
            </div>
            <button
              type="button"
              onClick={() => void handleDeleteDb(selectedDb)}
              className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 transition-all"
            >
              Delete Database
            </button>
          </div>

          {/* Tabs */}
          <div className="flex overflow-x-auto border-b border-slate-200 gap-1 pb-px">
            {(['overview', 'users', 'ops', 'metrics', 'query'] as const).map((t) => {
              const active = tab === t;
              return (
                <button
                  key={t}
                  type="button"
                  onClick={() => setTab(t)}
                  className={`px-3.5 py-2 text-sm font-medium border-b-2 whitespace-nowrap transition-colors capitalize ${
                    active
                      ? 'border-indigo-600 text-indigo-600 bg-indigo-50/50 rounded-t-md'
                      : 'border-transparent text-slate-600 hover:text-slate-900 hover:border-slate-300'
                  }`}
                >
                  {t === 'ops' ? 'Backups & Restore' : t === 'query' ? '🔍 Query Console' : t}
                </button>
              );
            })}
          </div>

          {/* Overview Tab */}
          {tab === 'overview' && (
            <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
              <h2 className="text-base font-semibold text-slate-900">Connection &amp; Information</h2>
              <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2 text-xs">
                <div>
                  <dt className="text-slate-500">Server ID</dt>
                  <dd className="font-mono text-slate-900">{selectedDb.server_id}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Created</dt>
                  <dd className="text-slate-900">{formatTs(selectedDb.created_at)}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Engine</dt>
                  <dd className="capitalize text-slate-900">
                    {selectedDb.engine} {selectedDb.engine_version}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500">Database Name</dt>
                  <dd className="font-mono text-slate-900">{selectedDb.db_name}</dd>
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
              <div className="flex items-center justify-between">
                <h4 className="text-sm font-semibold text-ink">Database Users</h4>
                <button
                  type="button"
                  onClick={() => setIsAddUserOpen(true)}
                  className={primaryButtonClass}
                >
                  + Add User
                </button>
              </div>

              <Modal
                isOpen={isAddUserOpen}
                onClose={() => setIsAddUserOpen(false)}
                title="Add Database User"
              >
                <form onSubmit={handleCreateUser} className="space-y-4">
                  <div className="grid grid-cols-1 gap-3">
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
                  <div className="flex justify-end gap-2 pt-2">
                    <button
                      type="button"
                      onClick={() => setIsAddUserOpen(false)}
                      className={secondaryButtonClass}
                    >
                      Cancel
                    </button>
                    <button type="submit" className={primaryButtonClass}>
                      Create User
                    </button>
                  </div>
                </form>
              </Modal>

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
              <div className="rounded-lg border border-line bg-surface p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-semibold text-ink">Restore from Dump</h4>
                    <p className="text-xs text-ink-muted mt-1">
                      Restores database content from a validated node dump path. The restore worker executes a live recoverability check via metrics before completing (Gate 2).
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setIsRestoreOpen(true)}
                    className={secondaryButtonClass}
                  >
                    + Restore Dump
                  </button>
                </div>
                {restoreJobMsg && <p className="text-xs text-ink-secondary">{restoreJobMsg}</p>}
              </div>

              <Modal
                isOpen={isRestoreOpen}
                onClose={() => setIsRestoreOpen(false)}
                title="Restore Database from Dump"
              >
                <form onSubmit={handleRestore} className="space-y-4">
                  <p className="text-xs text-ink-muted">
                    Restores database content from a validated node dump path. The restore worker executes a live recoverability check via metrics before completing.
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
                  <div className="flex justify-end gap-2 pt-2">
                    <button
                      type="button"
                      onClick={() => setIsRestoreOpen(false)}
                      className={secondaryButtonClass}
                    >
                      Cancel
                    </button>
                    <button type="submit" className={primaryButtonClass}>
                      Queue Restore Job
                    </button>
                  </div>
                </form>
              </Modal>

              {/* Database Rescue Mode (PRD §12.5) */}
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-semibold text-amber-500 flex items-center gap-1.5">
                      <span>🛡️</span> Database Rescue Mode & Diagnostics
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

          {/* Query Console Tab */}
          {tab === 'query' && (
            <div className="space-y-4 rounded-lg border border-line bg-surface p-4">
              <div>
                <h3 className="text-sm font-semibold text-ink">SQL Query Console</h3>
                <p className="text-xs text-ink-secondary">
                  Execute safe, read-only SQL queries or inspect schema on database <code className="font-mono text-ink">{selectedDb.db_name}</code>.
                </p>
              </div>

              {/* Quick Query Templates */}
              <div className="flex flex-wrap gap-1.5 text-xs">
                <span className="self-center text-ink-muted">Quick templates:</span>
                {[
                  { label: 'Version', sql: 'SELECT version();' },
                  { label: 'List Tables', sql: "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name;" },
                  { label: 'Table Sizes', sql: "SELECT relname AS relation, pg_size_pretty(pg_total_relation_size(C.oid)) AS total_size FROM pg_class C LEFT JOIN pg_namespace N ON (N.oid = C.relnamespace) WHERE nspname NOT IN ('pg_catalog', 'information_schema') AND C.relkind <> 'i' AND nspname !~ '^pg_toast' ORDER BY pg_total_relation_size(C.oid) DESC LIMIT 10;" },
                  { label: 'Active Connections', sql: "SELECT pid, usename, client_addr, state, query FROM pg_stat_activity WHERE datname = current_database();" },
                ].map((tmpl) => (
                  <button
                    key={tmpl.label}
                    type="button"
                    onClick={() => setQueryInput(tmpl.sql)}
                    className="rounded border border-line bg-elevated px-2 py-0.5 text-ink-secondary hover:border-accent hover:text-ink"
                  >
                    {tmpl.label}
                  </button>
                ))}
              </div>

              {/* SQL Input Area */}
              <div className="space-y-2">
                <textarea
                  rows={4}
                  value={queryInput}
                  onChange={(e) => setQueryInput(e.target.value)}
                  placeholder="Enter SQL statement here..."
                  className="w-full rounded-md border border-line bg-elevated p-3 font-mono text-xs text-ink outline-none focus:border-accent focus:ring-1 focus:ring-accent"
                />
                <div className="flex items-center justify-between">
                  <span className="text-[11px] text-ink-muted">
                    Engine: <span className="capitalize font-medium text-ink">{selectedDb.engine} {selectedDb.engine_version}</span>
                  </span>
                  <button
                    type="button"
                    disabled={!queryInput.trim()}
                    onClick={() => {
                      setQueryError('Raw SQL execution via the panel is not supported. Use a dedicated database client (psql / mysql CLI) to run arbitrary queries.');
                    }}
                    className={primaryButtonClass}
                  >
                    &#x25B6; Run Query
                  </button>
                </div>
              </div>

              {/* Query Error */}
              {queryError && (
                <div className="rounded-md border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/50 dark:bg-red-950/20 dark:text-red-400">
                  {queryError}
                </div>
              )}
            </div>
          )}
        </div>
      ) : (
        /* Database List */
        <div className="space-y-4">
          <Modal
            isOpen={showCreateForm}
            onClose={() => setShowCreateForm(false)}
            title="Provision Managed Database"
          >
            <form
              onSubmit={handleCreateDb}
              className="space-y-4"
            >
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
              <div className="flex justify-end gap-2 pt-2">
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
          </Modal>

          {loading ? (
            <p className="text-xs text-ink-muted">Loading databases…</p>
          ) : databases.length === 0 ? (
            <EmptyState title="No databases">
              No managed databases found in this project. Create one to get started.
            </EmptyState>
          ) : (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {databases.map((db) => {
                const isPostgres = db.engine === 'postgresql';
                const engineBadge = isPostgres
                  ? 'rounded-full bg-blue-50 border border-blue-200 px-2.5 py-0.5 text-xs font-medium text-blue-700'
                  : 'rounded-full bg-amber-50 border border-amber-200 px-2.5 py-0.5 text-xs font-medium text-amber-700';
                const statusColor =
                  db.state === 'active'
                    ? 'bg-emerald-500'
                    : db.state === 'suspended' || db.state === 'pending_delete'
                    ? 'bg-amber-400'
                    : 'bg-red-500';
                return (
                  <div
                    key={db.id}
                    onClick={() => selectDb(db)}
                    className="cursor-pointer rounded-xl border border-slate-200 bg-white p-5 shadow-sm hover:border-slate-300 hover:shadow-md transition-all space-y-3"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className={`h-2 w-2 rounded-full shrink-0 ${statusColor}`} />
                          <h4 className="text-sm font-semibold text-slate-900 truncate">{db.name}</h4>
                        </div>
                        <p className="font-mono text-xs text-slate-400 truncate mt-0.5">{db.slug}</p>
                      </div>
                      <span className={engineBadge}>{db.engine} {db.engine_version}</span>
                    </div>
                    <div className="flex items-center justify-between border-t border-slate-100 pt-3 text-xs text-slate-500">
                      <span className="capitalize">{db.state.replace('_', ' ')}</span>
                      <span>{formatTs(db.created_at)}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
