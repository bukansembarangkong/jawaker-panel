import { useEffect, useState } from 'react';
import { type OperationalState, EmptyState, ErrorNote, StatusBadge } from '../components/ui';
import { type CopilotApproval, type CopilotPlan, type CopilotSession, copilotApi } from '../api/client';

type Tab = 'sessions' | 'plans' | 'approvals';

const PROJECT_ID = 'default'; // ponytail: per-project selector; add when project switcher exists

function planState(state: string): OperationalState {
  const map: Record<string, OperationalState> = {
    draft: 'Pending',
    pending_approval: 'Running',
    approved: 'Healthy',
    rejected: 'Failed',
    applied: 'Healthy',
    cancelled: 'Disabled',
  };
  return map[state] ?? 'Unknown';
}

function riskColor(risk: string): string {
  const map: Record<string, string> = {
    low: 'text-green-600',
    medium: 'text-yellow-600',
    high: 'text-orange-600',
    critical: 'text-danger font-bold',
  };
  return map[risk] ?? 'text-ink';
}

// ── Sessions tab ──────────────────────────────────────────────────────────────

function SessionsTab() {
  const [sessions, setSessions] = useState<CopilotSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [creating, setCreating] = useState(false);
  const [intent, setIntent] = useState('');
  const [saving, setSaving] = useState(false);

  const load = () => {
    setLoading(true);
    copilotApi
      .listSessions(PROJECT_ID)
      .then((r) => setSessions(r.sessions ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const create = async () => {
    setSaving(true);
    try {
      await copilotApi.createSession(PROJECT_ID, intent.trim() || 'General analysis');
      setCreating(false);
      setIntent('');
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setSaving(false);
    }
  };

  const close = async (id: string) => {
    try {
      await copilotApi.closeSession(PROJECT_ID, id, 'completed');
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  if (loading) return <p className="text-ink-secondary text-sm">Loading sessions…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load sessions" onRetry={load} />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-ink">Copilot Sessions ({sessions.length})</h2>
        <button
          type="button"
          onClick={() => setCreating(true)}
          className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent/90"
        >
          New Session
        </button>
      </div>

      {creating && (
        <div className="rounded-md border border-line bg-surface p-4 space-y-3">
          <h3 className="text-sm font-medium text-ink">New Analysis Session</h3>
          <div>
            <label className="text-xs text-ink-secondary">What would you like to analyze or plan?</label>
            <input
              type="text"
              value={intent}
              onChange={(e) => setIntent(e.target.value)}
              placeholder="e.g. Explain recent CPU spike on server-01"
              className="mt-1 w-full rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
            />
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => void create()}
              disabled={saving}
              className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent/90 disabled:opacity-50"
            >
              {saving ? 'Starting…' : 'Start'}
            </button>
            <button
              type="button"
              onClick={() => { setCreating(false); setIntent(''); }}
              className="rounded-md border border-line px-3 py-1.5 text-xs text-ink-secondary hover:text-ink"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {sessions.length === 0 ? (
        <EmptyState title="No copilot sessions">
          <p className="text-sm text-ink-secondary">Start a session to analyze infrastructure or generate a change plan.</p>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line">
          {sessions.map((sess) => (
            <li key={sess.id} className="flex items-center justify-between gap-4 px-4 py-3">
              <div className="min-w-0">
                <p className="truncate text-sm text-ink">{sess.intent || '(no intent)'}</p>
                <p className="text-xs text-ink-muted">{sess.created_at.slice(0, 19).replace('T', ' ')} · {sess.user_id}</p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <span className={`text-xs ${sess.state === 'active' ? 'text-green-600' : 'text-ink-muted'}`}>
                  {sess.state}
                </span>
                {sess.state === 'active' && (
                  <button
                    type="button"
                    onClick={() => void close(sess.id)}
                    className="text-xs text-ink-secondary hover:text-ink"
                  >
                    Close
                  </button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── Plans tab ─────────────────────────────────────────────────────────────────

function PlansTab() {
  const [plans, setPlans] = useState<CopilotPlan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const load = () => {
    setLoading(true);
    copilotApi
      .listPlans(PROJECT_ID)
      .then((r) => setPlans(r.plans ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const submit = async (id: string) => {
    try {
      await copilotApi.submitPlan(PROJECT_ID, id);
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  const cancel = async (id: string) => {
    if (!window.confirm('Cancel this plan?')) return;
    try {
      await copilotApi.cancelPlan(PROJECT_ID, id);
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  if (loading) return <p className="text-ink-secondary text-sm">Loading plans…</p>;
  if (error) return <ErrorNote error={error} title="Failed to load plans" onRetry={load} />;

  return (
    <div className="space-y-4">
      <h2 className="text-sm font-medium text-ink">Change Plans ({plans.length})</h2>

      {plans.length === 0 ? (
        <EmptyState title="No change plans">
          <p className="text-sm text-ink-secondary">AI-generated change plans appear here for review and approval.</p>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line">
          {plans.map((plan) => (
            <li key={plan.id} className="px-4 py-3 space-y-1">
              <div className="flex items-center justify-between gap-4">
                <div className="min-w-0">
                  <p className="font-medium text-sm text-ink">{plan.title}</p>
                  <p className="text-xs text-ink-muted">{plan.created_at.slice(0, 19).replace('T', ' ')} · {plan.created_by}</p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className={`text-xs ${riskColor(plan.risk_level)}`}>{plan.risk_level} risk</span>
                  <StatusBadge state={planState(plan.state)} detail={plan.state} />
                  {plan.state === 'draft' && (
                    <>
                      <button
                        type="button"
                        onClick={() => void submit(plan.id)}
                        className="text-xs text-ink-secondary hover:text-ink"
                      >
                        Submit
                      </button>
                      <button
                        type="button"
                        onClick={() => void cancel(plan.id)}
                        className="text-xs text-ink-secondary hover:text-danger"
                      >
                        Cancel
                      </button>
                    </>
                  )}
                </div>
              </div>
              {plan.description && <p className="text-xs text-ink-secondary">{plan.description}</p>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── Approvals tab ─────────────────────────────────────────────────────────────

function ApprovalsTab() {
  const [plans, setPlans] = useState<CopilotPlan[]>([]);
  const [selectedPlan, setSelectedPlan] = useState('');
  const [approvals, setApprovals] = useState<CopilotApproval[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    copilotApi
      .listPlans(PROJECT_ID)
      .then((r) => {
        const ps = (r.plans ?? []).filter((p) => p.state === 'pending_approval');
        setPlans(ps);
        if (ps.length > 0) setSelectedPlan(ps[0].id);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))));
  }, []);

  useEffect(() => {
    if (!selectedPlan) return;
    setLoading(true);
    copilotApi
      .listApprovals(PROJECT_ID, selectedPlan)
      .then((r) => setApprovals(r.approvals ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, [selectedPlan]);

  const review = async (id: string, state: string) => {
    try {
      await copilotApi.reviewApproval(PROJECT_ID, selectedPlan, id, state, '');
      setApprovals((prev) => prev.map((a) => a.id === id ? { ...a, state } : a));
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  if (error) return <ErrorNote error={error} title="Failed to load approvals" onRetry={() => setError(null)} />;

  return (
    <div className="space-y-4">
      {plans.length === 0 ? (
        <EmptyState title="No pending approvals">
          <p className="text-sm text-ink-secondary">High-risk plans pending approval appear here.</p>
        </EmptyState>
      ) : (
        <>
          <div className="flex items-center gap-3">
            <label className="text-sm text-ink-secondary">Plan</label>
            <select
              value={selectedPlan}
              onChange={(e) => setSelectedPlan(e.target.value)}
              className="rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
            >
              {plans.map((p) => <option key={p.id} value={p.id}>{p.title}</option>)}
            </select>
          </div>

          {loading ? (
            <p className="text-ink-secondary text-sm">Loading approvals…</p>
          ) : (
            <ul className="divide-y divide-line rounded-md border border-line">
              {approvals.map((a) => (
                <li key={a.id} className="flex items-center justify-between gap-4 px-4 py-3">
                  <div>
                    <p className="text-sm text-ink">Requested by {a.requested_by}</p>
                    <p className="text-xs text-ink-muted">
                      Expires {a.expires_at.slice(0, 19).replace('T', ' ')}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className={`text-xs ${a.state === 'pending' ? 'text-yellow-600' : a.state === 'approved' ? 'text-green-600' : 'text-danger'}`}>
                      {a.state}
                    </span>
                    {a.state === 'pending' && (
                      <>
                        <button
                          type="button"
                          onClick={() => void review(a.id, 'approved')}
                          className="text-xs text-green-600 hover:text-green-700"
                        >
                          Approve
                        </button>
                        <button
                          type="button"
                          onClick={() => void review(a.id, 'rejected')}
                          className="text-xs text-danger hover:text-red-700"
                        >
                          Reject
                        </button>
                      </>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}

// ── Page shell ────────────────────────────────────────────────────────────────

export function CopilotPage() {
  const [tab, setTab] = useState<Tab>('sessions');

  const tabs: { id: Tab; label: string }[] = [
    { id: 'sessions', label: 'Sessions' },
    { id: 'plans', label: 'Change Plans' },
    { id: 'approvals', label: 'Approvals' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold tracking-wide text-ink">AI Infrastructure Copilot</h1>
        <p className="mt-1 text-sm text-ink-secondary">
          Read-only analysis, change plan generation, and policy-checked approval workflow.
          All tool calls are audited. No unrestricted shell access.
        </p>
      </div>

      <div className="flex gap-1 border-b border-line">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-sm ${
              tab === t.id
                ? 'border-b-2 border-accent font-medium text-ink'
                : 'text-ink-secondary hover:text-ink'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div>
        {tab === 'sessions' && <SessionsTab />}
        {tab === 'plans' && <PlansTab />}
        {tab === 'approvals' && <ApprovalsTab />}
      </div>
    </div>
  );
}
