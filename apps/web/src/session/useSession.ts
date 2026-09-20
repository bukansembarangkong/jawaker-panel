import { useCallback, useEffect, useRef, useState } from 'react';

import {
  ApiError,
  api,
  clearCsrf,
  isUnauthenticated,
  primeCsrf,
  type AuthSession,
  type VersionInfo,
} from '../api/client';

/**
 * Session lifecycle for the shell.
 *
 * States are explicit rather than a pair of booleans, because "we have not
 * asked yet" and "we asked and the answer was no" drive different UI: the first
 * shows a spinner, the second shows the login form. Collapsing them produces a
 * login form that flashes before the session check returns.
 */
export type SessionState =
  | { kind: 'loading' }
  | { kind: 'anonymous'; requiresBootstrap: boolean }
  | { kind: 'authenticated'; session: AuthSession };

export interface SessionController {
  state: SessionState;
  /** Version metadata, fetched alongside the session for the status panel. */
  version: VersionInfo | null;
  /** Set when the controller itself is unreachable; distinct from "no session". */
  controllerError: ApiError | Error | null;
  refresh: () => Promise<void>;
  signedIn: (session: AuthSession) => void;
  signOut: () => Promise<void>;
}

export function useSession(): SessionController {
  const [state, setState] = useState<SessionState>({ kind: 'loading' });
  const [version, setVersion] = useState<VersionInfo | null>(null);
  const [controllerError, setControllerError] = useState<ApiError | Error | null>(null);

  // Guards against a state update after unmount, which StrictMode double-invokes
  // in development.
  const mounted = useRef(true);

  const refresh = useCallback(async () => {
    setControllerError(null);
    try {
      // The CSRF token is primed before anything mutating can be attempted.
      // Failing to prime is not fatal for the read path, so it does not gate
      // the session check.
      await primeCsrf().catch(() => undefined);

      const [session, info] = await Promise.all([
        api.getSession().catch((err: unknown) => {
          if (isUnauthenticated(err)) {
            return null;
          }
          throw err;
        }),
        api.getVersion(),
      ]);

      if (!mounted.current) {
        return;
      }
      setVersion(info);

      if (session) {
        setState({ kind: 'authenticated', session });
        return;
      }
      const bootstrap = await api.bootstrapStatus();
      if (!mounted.current) {
        return;
      }
      setState({ kind: 'anonymous', requiresBootstrap: bootstrap.requires_bootstrap });
    } catch (err) {
      if (!mounted.current) {
        return;
      }
      // The controller is unreachable or answered incoherently. This is NOT the
      // same as being signed out, and must not render a login form: the user
      // would type credentials into a panel that cannot check them.
      setControllerError(err instanceof Error ? err : new Error(String(err)));
      setState({ kind: 'loading' });
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    void refresh();
    return () => {
      mounted.current = false;
    };
  }, [refresh]);

  const signedIn = useCallback((session: AuthSession) => {
    setState({ kind: 'authenticated', session });
  }, []);

  const signOut = useCallback(async () => {
    await api.logout().catch(() => {
      // The session may already be gone (expired, revoked elsewhere). Locally
      // clearing the token is the honest outcome either way.
      clearCsrf();
    });
    if (mounted.current) {
      setState({ kind: 'anonymous', requiresBootstrap: false });
    }
  }, []);

  return { state, version, controllerError, refresh, signedIn, signOut };
}
