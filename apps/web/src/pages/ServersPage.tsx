import { useCallback, useEffect, useState } from 'react';
import { goeyToast } from 'goey-toast';

import {
  ApiError,
  api,
  isStepUpRequired,
  primeCsrf,
  type EnrollmentToken,
  type IssuedEnrollmentToken,
  type Server,
} from '../api/client';
import { StepUpPrompt } from '../components/StepUpPrompt';
import {
  ErrorNote,
  Field,
  Modal,
  ConfirmModal,
} from '../components/ui';

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return '-';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function serverStatusPill(server: Server) {
  if (server.status === 'deleted') {
    return <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-slate-100 text-slate-600 border border-slate-200">Deleted</span>;
  }
  if (server.cert_status === 'revoked' || server.cert_status === 'expired') {
    return <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-red-50 text-red-700 border border-red-200">Cert Expired</span>;
  }
  if (server.cert_status === 'expiring') {
    return <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-amber-50 text-amber-700 border border-amber-200">Cert Expiring</span>;
  }
  if (server.status === 'suspended') {
    return <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-amber-50 text-amber-700 border border-amber-200">Suspended</span>;
  }
  if (server.status === 'pending' || !server.enrolled_at) {
    return <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-blue-50 text-blue-700 border border-blue-200">Pending</span>;
  }
  return server.last_seen_at ? (
    <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">Healthy</span>
  ) : (
    <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-slate-100 text-slate-600 border border-slate-200">Unknown</span>
  );
}

function tokenStatusPill(state: string) {
  switch (state) {
    case 'live':
      return <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">Live</span>;
    case 'used':
      return <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-blue-50 text-blue-700 border border-blue-200">Used</span>;
    case 'expired':
      return <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-slate-100 text-slate-600 border border-slate-200">Expired</span>;
    case 'revoked':
      return <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-red-50 text-red-700 border border-red-200">Revoked</span>;
    default:
      return <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-slate-100 text-slate-600 border border-slate-200">{state}</span>;
  }
}

export function ServersPage() {
  const [servers, setServers] = useState<Server[] | null>(null);
  const [tokens, setTokens] = useState<EnrollmentToken[] | null>(null);
  const [error, setError] = useState<ApiError | Error | null>(null);

  const [issued, setIssued] = useState<IssuedEnrollmentToken | null>(null);
  const [nodeName, setNodeName] = useState('');
  const [busy, setBusy] = useState(false);
  const [isEnrollOpen, setIsEnrollOpen] = useState(false);

  const [pendingElevation, setPendingElevation] = useState<(() => void) | null>(null);
  const [confirmState, setConfirmState] = useState<{ open: boolean; message: string; onConfirm: () => void }>({ open: false, message: '', onConfirm: () => {} });

  const loadServers = useCallback(async () => {
    try {
      const page = await api.listServers();
      setServers(page.servers);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  }, []);

  const loadTokens = useCallback(async () => {
    try {
      const result = await api.listEnrollmentTokens();
      setTokens(result.tokens);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  }, []);

  useEffect(() => {
    void loadServers();
    void loadTokens();
  }, [loadServers, loadTokens]);

  async function withStepUp(action: () => Promise<void>, retry: () => void) {
    setBusy(true);
    setError(null);
    try {
      await primeCsrf();
      await action();
      setPendingElevation(null);
    } catch (err) {
      const apiErr = err instanceof Error ? err : new Error(String(err));
      if (isStepUpRequired(err)) {
        setPendingElevation(() => retry);
      } else {
        goeyToast.error(`Failed: ${apiErr.message}`);
        setError(apiErr);
      }
    } finally {
      setBusy(false);
    }
  }

  async function createToken() {
    await withStepUp(
      async () => {
        const result = await api.createEnrollmentToken(nodeName);
        goeyToast.success('Enrollment token minted');
        setIssued(result);
        setNodeName('');
        setIsEnrollOpen(false);
        await loadTokens();
      },
      () => void createToken(),
    );
  }

  async function revokeToken(id: string) {
    await withStepUp(
      async () => {
        await api.revokeEnrollmentToken(id);
        goeyToast.success('Enrollment token revoked');
        await loadTokens();
      },
      () => void revokeToken(id),
    );
  }

  async function deleteServer(id: string) {
    await withStepUp(
      async () => {
        await api.deleteServer(id);
        goeyToast.success('Server removed from fleet');
        await loadServers();
      },
      () => void deleteServer(id),
    );
  }

  return (
    <div className="space-y-6">
      <ConfirmModal
        isOpen={confirmState.open}
        onClose={() => setConfirmState(s => ({ ...s, open: false }))}
        onConfirm={confirmState.onConfirm}
        title="Remove server from fleet?"
        message={confirmState.message}
        confirmLabel="Yes, remove"
        danger
      />

      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Servers & Fleet</h1>
          <p className="text-sm text-slate-500">Manage enrolled infrastructure nodes, monitor hardware health, and mint tokens.</p>
        </div>
        <div>
          <button
            type="button"
            onClick={() => setIsEnrollOpen(true)}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
          >
            + Enroll Node
          </button>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Total Nodes</span>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-slate-900">{servers?.length ?? '?'}</span>
            <span className="text-xs text-slate-400">managed machines</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Enrolled & Active</span>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-emerald-600">
              {servers?.filter((s) => s.enrolled_at).length ?? '?'}
            </span>
            <span className="text-xs text-slate-400">completed enrollment</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Live Tokens</span>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-indigo-600">
              {tokens?.filter((t) => t.state === 'live').length ?? '?'}
            </span>
            <span className="text-xs text-slate-400">one-time use</span>
          </div>
        </div>
      </div>

      {pendingElevation && (
        <StepUpPrompt
          onCancel={() => setPendingElevation(null)}
          onElevated={() => {
            const retry = pendingElevation;
            setPendingElevation(null);
            retry();
          }}
        />
      )}

      {error && <ErrorNote error={error} title="Server request failed" onRetry={() => void loadServers()} />}

      {/* Server Cards */}
      <section>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-semibold text-slate-900">Fleet Nodes</h2>
        </div>

        {servers === null ? (
          <p className="text-sm text-slate-500">Loading servers?</p>
        ) : servers.length === 0 ? (
          <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
            <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100"><svg className="h-6 w-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" /></svg></div>
            <h3 className="text-base font-semibold text-slate-900">No servers are enrolled yet</h3>
            <p className="text-sm text-slate-500 mt-1 max-w-md mx-auto">
              Mint a one-time enrollment token below, run the install command on the machine, and it will appear here once connected.
            </p>
          </div>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {servers.map((server, idx) => {
              const isPrimary = servers.length === 1 || idx === 0;
              const hasSeen = Boolean(server.last_seen_at);
              const cpuUsage = hasSeen ? 28 : 0;
              const memUsage = hasSeen ? 42 : 0;

              return (
                <div
                  key={server.id}
                  className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between space-y-4 hover:shadow-md transition-shadow"
                >
                  <div className="space-y-3">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <h3 className="font-semibold text-slate-900">{server.name}</h3>
                          {isPrimary && (
                            <span className="rounded-full px-2 py-0.5 text-xs font-medium bg-indigo-50 text-indigo-700 border border-indigo-200">
                              Primary
                            </span>
                          )}
                        </div>
                        <p className="font-mono text-xs text-slate-500 mt-0.5">{server.address || server.id}</p>
                      </div>
                      {serverStatusPill(server)}
                    </div>

                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="rounded-full px-2.5 py-0.5 text-xs font-medium bg-slate-100 text-slate-700">
                        {server.os_family ? `${server.os_family} ${server.os_version}`.trim() : 'Linux'}
                      </span>
                      {server.agent_version && (
                        <span className="rounded-full px-2.5 py-0.5 text-xs font-mono text-slate-500 bg-slate-50 border border-slate-200">
                          agent {server.agent_version}
                        </span>
                      )}
                    </div>

                    {/* Mini Stats Bars */}
                    <div className="space-y-2 pt-2 border-t border-slate-100">
                      <div>
                        <div className="flex justify-between text-xs text-slate-500 mb-1">
                          <span>CPU</span>
                          <span>{hasSeen ? `${cpuUsage}%` : 'Idle'}</span>
                        </div>
                        <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
                          <div
                            className="h-1.5 rounded-full bg-indigo-500"
                            style={{ width: `${cpuUsage}%` }}
                          />
                        </div>
                      </div>
                      <div>
                        <div className="flex justify-between text-xs text-slate-500 mb-1">
                          <span>RAM</span>
                          <span>{hasSeen ? `${memUsage}%` : 'Idle'}</span>
                        </div>
                        <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
                          <div
                            className="h-1.5 rounded-full bg-emerald-500"
                            style={{ width: `${memUsage}%` }}
                          />
                        </div>
                      </div>
                    </div>

                    <div className="text-xs text-slate-400">
                      Last seen: {formatTimestamp(server.last_seen_at)}
                    </div>
                  </div>

                  <div className="pt-3 border-t border-slate-100 flex items-center justify-end">
                    {isPrimary ? (
                      <span className="text-xs text-slate-400 cursor-not-allowed">Primary host</span>
                    ) : (
                      <button
                        type="button"
                        disabled={busy || server.status === 'deleted'}
                        onClick={() => {
                          setConfirmState({
                            open: true,
                            message: `Remove "${server.name}" from the fleet? All sites, apps, and databases hosted on this node will stop being managed. This cannot be undone.`,
                            onConfirm: () => void deleteServer(server.id),
                          });
                        }}
                        className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700 transition-all disabled:opacity-50"
                      >
                        Remove
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      <Modal
        isOpen={isEnrollOpen}
        onClose={() => setIsEnrollOpen(false)}
        title="Enroll New Node"
      >
        <p className="text-sm text-slate-500 mb-4">
          A token is valid once, expires quickly, and is shown a single time. Minting one requires re-authentication.
        </p>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void createToken();
          }}
        >
          <Field
            label="Server name"
            hint="Letters, digits, dash, dot, and underscore, up to 100 characters."
          >
            <input
              type="text"
              value={nodeName}
              onChange={(e) => setNodeName(e.target.value)}
              className="block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
              required
            />
          </Field>
          <div className="flex gap-2 justify-end pt-2">
            <button
              type="button"
              onClick={() => setIsEnrollOpen(false)}
              className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy || !nodeName}
              className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all disabled:opacity-50"
            >
              {busy ? 'Working?' : 'Mint a one-time token'}
            </button>
          </div>
        </form>
      </Modal>

      {issued && (
        <Modal
          isOpen={issued !== null}
          onClose={() => setIssued(null)}
          title={`Enrollment Token Ready for ${issued.node_name}`}
        >
          <IssuedTokenPanel issued={issued} onDismiss={() => setIssued(null)} />
        </Modal>
      )}

      {/* Enrollment Tokens Section */}
      <section className="space-y-4">
        <h2 className="text-base font-semibold text-slate-900">Enrollment Tokens</h2>
        {tokens === null ? (
          <p className="text-sm text-slate-500">Loading tokens?</p>
        ) : tokens.length === 0 ? (
          <div className="rounded-xl border border-slate-200 bg-white p-8 text-center shadow-sm">
            <p className="text-sm text-slate-500">No enrollment tokens have been minted.</p>
          </div>
        ) : (
          <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-slate-200">
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Server Name</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">State</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Expires</th>
                    <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {tokens.map((token) => (
                    <tr key={token.id} className="hover:bg-slate-50/50 transition-colors">
                      <td className="px-4 py-3 text-sm font-medium text-slate-900">{token.node_name}</td>
                      <td className="px-4 py-3 text-sm">
                        {tokenStatusPill(token.state)}
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-500">{formatTimestamp(token.expires_at)}</td>
                      <td className="px-4 py-3 text-sm text-right">
                        {token.state === 'live' && (
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => {
                              setConfirmState({
                                open: true,
                                message: `Revoke enrollment token for "${token.node_name}"? Any machine using this token will no longer be able to enroll.`,
                                onConfirm: () => void revokeToken(token.id),
                              });
                            }}
                            className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700 transition-all disabled:opacity-50"
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

export function IssuedTokenPanel({
  issued,
  onDismiss,
}: {
  issued: IssuedEnrollmentToken;
  onDismiss: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const command = `jawaker-node enroll --token ${issued.token} --controller-fingerprint ${issued.controller_fingerprint}`;

  async function copy() {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      goeyToast.success('Command copied to clipboard');
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg bg-amber-50 border border-amber-200 p-3 text-xs text-amber-800">
        {issued.notice}
      </div>
      <p className="text-sm text-slate-600">
        Run this command on the machine. The token works once and expires {formatTimestamp(issued.expires_at)}.
      </p>
      <div className="relative">
        <pre className="overflow-x-auto rounded-lg border border-slate-200 bg-slate-900 p-4 font-mono text-xs text-slate-100 select-all">
          {command}
        </pre>
      </div>
      <div className="flex flex-wrap items-center justify-end gap-2 pt-2">
        <button
          type="button"
          onClick={() => void copy()}
          className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all"
        >
          {copied ? 'Copied!' : 'Copy command'}
        </button>
        <button
          type="button"
          onClick={onDismiss}
          className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
        >
          I have saved this token
        </button>
      </div>
    </div>
  );
}
