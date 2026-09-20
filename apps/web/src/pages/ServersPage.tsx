import { useCallback, useEffect, useState } from 'react';

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
  EmptyState,
  ErrorNote,
  Field,
  MetricCard,
  StatusBadge,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
  type OperationalState,
} from '../components/ui';

/**
 * Servers: the fleet list, one-time enrollment tokens, and the step-up prompt
 * that makes minting one possible.
 *
 * Three things here are deliberate and worth stating, because each one is a
 * place where a plausible-looking shortcut produces a lie:
 *
 *  - The token plaintext is rendered ONCE, from the create response, and is
 *    never written to localStorage or module state. The server stores only its
 *    digest, so a UI that appeared to "reload" it later would be inventing a
 *    credential it does not have.
 *  - A 403 `step_up_required` is a PROMPT, not a failure. Rendering it as
 *    "denied" would tell the operator they lack a permission they actually
 *    hold, and they would go looking for a role change that is not needed.
 *  - The list is server-side truth. Nothing here filters by permission: hiding
 *    a control is cosmetic and the server re-checks every request (PRD rule: no
 *    authorization rule may exist only in frontend code).
 */

/** mapServerState translates a server row into a display state. */
function mapServerState(server: Server): OperationalState {
  if (server.status === 'deleted') return 'Disabled';
  if (server.cert_status === 'revoked') return 'Critical';
  if (server.cert_status === 'expired') return 'Critical';
  if (server.cert_status === 'expiring') return 'Warning';
  if (server.status === 'suspended') return 'Paused';
  if (server.status === 'pending' || !server.enrolled_at) return 'Pending';
  // An enrolled, active server with a live certificate that has never been
  // heard from is not "healthy": nothing has confirmed it is reachable. Green
  // here would be an assertion the controller cannot back.
  return server.last_seen_at ? 'Healthy' : 'Unknown';
}

/** certLabel renders the certificate state in words, never by colour alone. */
function certLabel(server: Server): string {
  switch (server.cert_status) {
    case 'active':
      return 'Certificate active';
    case 'expiring':
      return 'Certificate expiring';
    case 'expired':
      return 'Certificate expired';
    case 'revoked':
      return 'Certificate revoked';
    default:
      return 'No certificate';
  }
}

function tokenState(token: EnrollmentToken): OperationalState {
  switch (token.state) {
    case 'live':
      return 'Pending';
    case 'used':
      return 'Healthy';
    case 'expired':
      return 'Disabled';
    case 'revoked':
      return 'Critical';
    default:
      return 'Unknown';
  }
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

export function ServersPage() {
  const [servers, setServers] = useState<Server[] | null>(null);
  const [tokens, setTokens] = useState<EnrollmentToken[] | null>(null);
  const [error, setError] = useState<ApiError | Error | null>(null);

  const [issued, setIssued] = useState<IssuedEnrollmentToken | null>(null);
  const [nodeName, setNodeName] = useState('');
  const [busy, setBusy] = useState(false);

  // The pending action that a step-up refusal interrupted. Re-running it is the
  // caller's decision, not an automatic retry: the operator has just typed a
  // password and should see the action complete, not have it replay silently.
  const [pendingElevation, setPendingElevation] = useState<(() => void) | null>(null);

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
      // The token list is supplementary to the fleet view: a failure to read it
      // must not blank the server list, which is the primary content. It is
      // reported and the rest of the page stays usable.
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  }, []);

  useEffect(() => {
    void loadServers();
    void loadTokens();
  }, [loadServers, loadTokens]);

  /**
   * Runs a mutating call, converting a step-up refusal into a prompt.
   *
   * Every path that can be refused for lack of elevation goes through here, so
   * the prompt cannot be forgotten on one of them and left as a bare "denied".
   */
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
        setIssued(result);
        setNodeName('');
        await loadTokens();
      },
      () => void createToken(),
    );
  }

  async function revokeToken(id: string) {
    await withStepUp(
      async () => {
        await api.revokeEnrollmentToken(id);
        await loadTokens();
      },
      () => void revokeToken(id),
    );
  }

  async function deleteServer(id: string) {
    await withStepUp(
      async () => {
        await api.deleteServer(id);
        await loadServers();
      },
      () => void deleteServer(id),
    );
  }

  if (servers === null && tokens === null && !error) {
    return (
      <p role="status" className="text-sm text-ink-secondary">
        Loading servers…
      </p>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-3">
        <MetricCard label="Servers" value={servers?.length ?? '…'} mono />
        <MetricCard
          label="Enrolled"
          value={servers?.filter((s) => s.enrolled_at).length ?? '…'}
          mono
          hint="Servers that completed enrollment."
        />
        <MetricCard
          label="Enrollment tokens"
          value={tokens?.filter((t) => t.state === 'live').length ?? '…'}
          mono
          hint="Live tokens; each works once."
        />
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

      <section aria-labelledby="fleet-heading">
        <h2 id="fleet-heading" className="text-base font-semibold text-ink">
          Fleet
        </h2>
        {servers === null ? (
          <p role="status" className="mt-2 text-sm text-ink-secondary">
            Loading servers…
          </p>
        ) : servers.length === 0 ? (
          <div className="mt-3">
            <EmptyState title="No servers are enrolled yet">
              Mint a one-time enrollment token below, run the install command on the machine, and it
              will appear here once it completes enrollment.
            </EmptyState>
          </div>
        ) : (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <caption className="sr-only">
                Enrolled servers. State is given in words; colour is never the only signal.
              </caption>
              <thead>
                <tr className="border-b border-line text-left text-xs uppercase tracking-wide text-ink-muted">
                  <th scope="col" className="py-2 pr-4">
                    Name
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    State
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    Certificate
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    OS
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    Last seen
                  </th>
                  <th scope="col" className="py-2">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {servers.map((server) => (
                  <tr key={server.id} className="border-b border-line align-top">
                    <td className="py-3 pr-4">
                      <p className="font-medium text-ink">{server.name}</p>
                      <p className="font-mono text-xs text-ink-muted">{server.address || server.id}</p>
                    </td>
                    <td className="py-3 pr-4">
                      <StatusBadge state={mapServerState(server)} />
                    </td>
                    <td className="py-3 pr-4 text-ink-secondary">{certLabel(server)}</td>
                    <td className="py-3 pr-4 text-ink-secondary">
                      {server.os_family
                        ? `${server.os_family} ${server.os_version}`.trim()
                        : 'Not reported'}
                    </td>
                    <td className="py-3 pr-4 text-ink-secondary">{formatTimestamp(server.last_seen_at)}</td>
                    <td className="py-3">
                      <button
                        type="button"
                        disabled={busy || server.status === 'deleted'}
                        onClick={() => void deleteServer(server.id)}
                        className={secondaryButtonClass}
                        aria-label={`Remove ${server.name} from the fleet`}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section aria-labelledby="enroll-heading" className="rounded-lg border border-line bg-surface p-5">
        <h2 id="enroll-heading" className="text-base font-semibold text-ink">
          Enroll a node
        </h2>
        <p className="mt-1 text-sm text-ink-secondary">
          A token is valid once, expires quickly, and is shown a single time. Minting one requires
          re-authentication, because it adds a machine to the fleet.
        </p>
        <form
          className="mt-4 space-y-4"
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
              className={inputClass}
              required
            />
          </Field>
          <button type="submit" disabled={busy || !nodeName} className={primaryButtonClass}>
            {busy ? 'Working…' : 'Mint a one-time token'}
          </button>
        </form>
      </section>

      {issued && <IssuedTokenPanel issued={issued} onDismiss={() => setIssued(null)} />}

      <section aria-labelledby="token-list-heading">
        <h2 id="token-list-heading" className="text-base font-semibold text-ink">
          Enrollment tokens
        </h2>
        {tokens === null ? (
          <p role="status" className="mt-2 text-sm text-ink-secondary">
            Loading tokens…
          </p>
        ) : tokens.length === 0 ? (
          <p className="mt-2 text-sm text-ink-secondary">No enrollment tokens have been minted.</p>
        ) : (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs uppercase tracking-wide text-ink-muted">
                  <th scope="col" className="py-2 pr-4">
                    Server name
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    State
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    Expires
                  </th>
                  <th scope="col" className="py-2">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {tokens.map((token) => (
                  <tr key={token.id} className="border-b border-line align-top">
                    <td className="py-3 pr-4 font-medium text-ink">{token.node_name}</td>
                    <td className="py-3 pr-4">
                      <StatusBadge state={tokenState(token)} detail={token.state} />
                    </td>
                    <td className="py-3 pr-4 text-ink-secondary">{formatTimestamp(token.expires_at)}</td>
                    <td className="py-3">
                      <button
                        type="button"
                        disabled={busy || token.state !== 'live'}
                        onClick={() => void revokeToken(token.id)}
                        className={secondaryButtonClass}
                        aria-label={`Revoke the token for ${token.node_name}`}
                      >
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

/**
 * IssuedTokenPanel shows the plaintext exactly once.
 *
 * The copy is deliberately explicit that it will not be retrievable, because it
 * will not be: the server keeps only a digest. A milder phrasing would let an
 * operator close this panel believing they can come back for it.
 */
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
    } catch {
      // Clipboard access can be denied (insecure context, permissions). The
      // command is on screen and selectable, so this is not a failure state
      // worth an error banner — but it must not claim to have copied.
      setCopied(false);
    }
  }

  return (
    <section
      aria-labelledby="issued-heading"
      className="rounded-lg border border-warn/50 bg-surface p-5"
    >
      <h2 id="issued-heading" className="text-base font-semibold text-ink">
        Enrollment token for {issued.node_name}
      </h2>
      <p className="mt-1 text-sm text-warn">{issued.notice}</p>
      <p className="mt-2 text-sm text-ink-secondary">
        Run this on the machine. The token works once and expires{' '}
        {formatTimestamp(issued.expires_at)}.
      </p>
      <pre className="mt-3 overflow-x-auto rounded-md border border-line bg-elevated p-3 font-mono text-xs text-ink">
        {command}
      </pre>
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button type="button" onClick={() => void copy()} className={secondaryButtonClass}>
          {copied ? 'Copied' : 'Copy command'}
        </button>
        <button type="button" onClick={onDismiss} className={primaryButtonClass}>
          I have saved this token
        </button>
      </div>
    </section>
  );
}
