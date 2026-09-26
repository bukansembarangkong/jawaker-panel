import { useEffect, useState } from 'react';
import { type OperationalState, ErrorNote, StatusBadge, ConfirmModal } from '../components/ui';
import { type CopilotApproval, type CopilotPlan, type CopilotSession, copilotApi } from '../api/client';
import { useFirstProjectId } from '../hooks/useFirstProjectId';

type Tab = 'sessions' | 'plans' | 'approvals';

function planState(state: string): OperationalState {
  const map: Record<string, OperationalState> = {
    draft: 'Pending', pending_approval: 'Running', approved: 'Healthy', rejected: 'Failed', applied: 'Healthy', cancelled: 'Disabled',
  };
  return map[state] ?? 'Unknown';
}

function riskPillClass(risk: string): string {
  switch (risk) {
    case 'low': return 'bg-emerald-50 text-emerald-700 border border-emerald-200';
    case 'medium': return 'bg-amber-50 text-amber-700 border border-amber-200';
    case 'high': return 'bg-orange-50 text-orange-700 border border-orange-200';
    case 'critical': return 'bg-red-50 text-red-700 border border-red-200 font-bold';
    default: return 'bg-slate-100 text-slate-600 border border-slate-200';
  }
}

function sessionPillClass(state: string): string {
  switch (state) {
    case 'active': return 'bg-emerald-50 text-emerald-700 border border-emerald-200';
    case 'closed': return 'bg-slate-100 text-slate-600 border border-slate-200';
    case 'expired': return 'bg-amber-50 text-amber-700 border border-amber-200';
    default: return 'bg-slate-100 text-slate-600 border border-slate-200';
  }
}

// ?? Sessions tab ??????????????????????????????????????????????????????????????

function SessionsTab() {
  const projectId = useFirstProjectId();
  const [sessions, setSessions] = useState<CopilotSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [creating, setCreating] = useState(false);
  const [intent, setIntent] = useState('');
  const [saving, setSaving] = useState(false);

  const load = () => {
    if (!projectId) return;
    setLoading(true);
    copilotApi.listSessions(projectId)
      .then((r) => setSessions(r.sessions ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { if (projectId) load(); }, [projectId]); // eslint-disable-line react-hooks/exhaustive-deps

  const create = async () => {
    if (!projectId) return;
    setSaving(true);
    try {
      await copilotApi.createSession(projectId, intent.trim() || 'General analysis');
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
    if (!projectId) return;
    try {
      await copilotApi.closeSession(projectId, id, 'completed');
      load();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  if (loading) return <p className="text-slate-500 text-sm">Loading sessions?</p>;
  if (error) return <ErrorNote error={error} title="Failed to load sessions" onRetry={load} />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-slate-700">
          {sessions.length} {sessions.length === 1 ? 'session' : 'sessions'}
        </span>
        <button
          type="button"
          onClick={() => setCreating(true)}
          className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
        >
          + New Session
        </button>
      </div>

      {creating && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <h3 className="font-semibold text-slate-900">New Analysis Session</h3>
          <div>
            <label className="block text-xs font-medium text-slate-600 mb-1">What would you like to analyze or plan?</label>
            <input
              type="text"
              value={intent}
              onChange={(e) => setIntent(e.target.value)}
              placeholder="e.g. Explain recent CPU spike on server-01"
              className="block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
            />
          </div>
          <div className="flex gap-2 justify-end">
            <button
              type="button"
              onClick={() => { setCreating(false); setIntent(''); }}
              className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-all"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => void create()}
              disabled={saving}
              className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all disabled:opacity-50"
            >
              {saving ? 'Starting?' : 'Start Session'}
            </button>
          </div>
        </div>
      )}

      {sessions.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
          <div className="text-4xl mb-3">??</div>
          <h3 className="text-base font-semibold text-slate-900">No copilot sessions</h3>
          <p className="text-sm text-slate-500 mt-1">Start a session to analyze infrastructure or generate a change plan.</p>
        </div>
      ) : (
        <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-slate-200">
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Session</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Started</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">User</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Status</th>
                  <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {sessions.map((sess) => (
                  <tr key={sess.id} className="hover:bg-slate-50/50 transition-colors">
                    <td className="px-4 py-3 text-sm">
                      <p className="font-medium text-slate-900 truncate max-w-xs">{sess.intent || '(no intent)'}</p>
                      <p className="font-mono text-xs text-slate-400">{sess.id.slice(0, 8)}?</p>
                    </td>
                    <td className="px-4 py-3 text-sm text-slate-500">{sess.created_at.slice(0, 19).replace('T', ' ')}</td>
                    <td className="px-4 py-3 text-sm text-slate-600">{sess.user_id}</td>
                    <td className="px-4 py-3 text-sm">
                      <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${sessionPillClass(sess.state)}`}>
                        {sess.state}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-right">
                      {sess.state === 'active' && (
                        <button
                          type="button"
                          onClick={() => void close(sess.id)}
                          className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-all"
                        >
                          Close
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
    </div>
  );
}

// ?? Plans tab ?????????????????????????????????????????????????????????????????

function PlansTab() {
  const projectId = useFirstProjectId();
  const [plans, setPlans] = useState<CopilotPlan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [confirmState, setConfirmState] = useState<{ open: boolean; message: string; onConfirm: () => void }>({ open: false, message: '', onConfirm: () => {} });

  const load = () => {
    if (!projectId) return;
    setLoading(true);
    copilotApi.listPlans(projectId)
      .then((r) => setPlans(r.plans ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  };

  useEffect(() => { if (projectId) load(); }, [projectId]); // eslint-disable-line react-hooks/exhaustive-deps

  const submit = async (id: string) => {
    if (!projectId) return;
    try { await copilotApi.submitPlan(projectId, id); load(); }
    catch (e) { setError(e instanceof Error ? e : new Error(String(e))); }
  };

  const cancel = async (id: string) => {
    if (!projectId) return;
    setConfirmState({
      open: true, message: 'Cancel this plan?',
      onConfirm: async () => {
        try { await copilotApi.cancelPlan(projectId, id); load(); }
        catch (e) { setError(e instanceof Error ? e : new Error(String(e))); }
      },
    });
  };

  if (loading) return <p className="text-slate-500 text-sm">Loading plans?</p>;
  if (error) return <ErrorNote error={error} title="Failed to load plans" onRetry={load} />;

  return (
    <div className="space-y-4">
      <ConfirmModal
        isOpen={confirmState.open}
        onClose={() => setConfirmState(s => ({ ...s, open: false }))}
        onConfirm={confirmState.onConfirm}
        title="Are you sure?"
        message={confirmState.message}
        confirmLabel="Yes, proceed"
        danger
      />

      {plans.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
          <div className="text-4xl mb-3">??</div>
          <h3 className="text-base font-semibold text-slate-900">No change plans</h3>
          <p className="text-sm text-slate-500 mt-1">AI-generated change plans appear here for review and approval.</p>
        </div>
      ) : (
        <div className="grid gap-4">
          {plans.map((plan) => {
            const taskCount = plan.steps?.length ?? 0;
            const doneTasks = 0;
            const progress = taskCount > 0 ? Math.round((doneTasks / taskCount) * 100) : 0;

            return (
              <div key={plan.id} className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="font-semibold text-slate-900">{plan.title}</h3>
                      <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${riskPillClass(plan.risk_level)}`}>
                        {plan.risk_level} risk
                      </span>
                      <StatusBadge state={planState(plan.state)} detail={plan.state} />
                    </div>
                    <p className="text-xs text-slate-400 mt-1">
                      {plan.created_at.slice(0, 19).replace('T', ' ')} ? {plan.created_by}
                    </p>
                  </div>
                  {plan.state === 'draft' && (
                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        type="button"
                        onClick={() => void submit(plan.id)}
                        className="rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
                      >
                        Submit for Review
                      </button>
                      <button
                        type="button"
                        onClick={() => void cancel(plan.id)}
                        className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700 transition-all"
                      >
                        Cancel
                      </button>
                    </div>
                  )}
                </div>

                {plan.description && <p className="text-sm text-slate-600">{plan.description}</p>}

                {taskCount > 0 && (
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-slate-500">Task progress</span>
                      <span className="text-xs font-medium text-slate-700">{doneTasks}/{taskCount} tasks done</span>
                    </div>
                    <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                      <div className="h-2 rounded-full bg-indigo-500 transition-all" style={{ width: `${progress}%` }} />
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ?? Approvals tab ?????????????????????????????????????????????????????????????

function ApprovalsTab() {
  const projectId = useFirstProjectId();
  const [plans, setPlans] = useState<CopilotPlan[]>([]);
  const [selectedPlan, setSelectedPlan] = useState('');
  const [approvals, setApprovals] = useState<CopilotApproval[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    if (!projectId) return;
    copilotApi.listPlans(projectId)
      .then((r) => {
        const ps = (r.plans ?? []).filter((p) => p.state === 'pending_approval');
        setPlans(ps);
        if (ps.length > 0) setSelectedPlan(ps[0].id);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))));
  }, [projectId]);

  useEffect(() => {
    if (!projectId || !selectedPlan) return;
    setLoading(true);
    copilotApi.listApprovals(projectId, selectedPlan)
      .then((r) => setApprovals(r.approvals ?? []))
      .catch((e: unknown) => setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => setLoading(false));
  }, [projectId, selectedPlan]);

  const review = async (id: string, state: string) => {
    if (!projectId) return;
    try {
      await copilotApi.reviewApproval(projectId, selectedPlan, id, state, '');
      setApprovals((prev) => prev.map((a) => a.id === id ? { ...a, state } : a));
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };

  if (error) return <ErrorNote error={error} title="Failed to load approvals" onRetry={() => setError(null)} />;

  return (
    <div className="space-y-4">
      {plans.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white p-12 text-center shadow-sm">
          <div className="text-4xl mb-3">?</div>
          <h3 className="text-base font-semibold text-slate-900">No pending approvals</h3>
          <p className="text-sm text-slate-500 mt-1">High-risk plans pending approval appear here.</p>
        </div>
      ) : (
        <>
          <div className="flex items-center gap-3">
            <label className="text-sm font-medium text-slate-600">Plan</label>
            <select
              value={selectedPlan}
              onChange={(e) => setSelectedPlan(e.target.value)}
              className="block rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
            >
              {plans.map((p) => <option key={p.id} value={p.id}>{p.title}</option>)}
            </select>
          </div>

          {loading ? (
            <p className="text-slate-500 text-sm">Loading approvals?</p>
          ) : (
            <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
              <div className="overflow-x-auto">
                {approvals.length === 0 ? (
                  <div className="p-8 text-center">
                    <p className="text-sm text-slate-500">No approval requests for this plan.</p>
                  </div>
                ) : (
                  <table className="w-full text-left">
                    <thead>
                      <tr className="border-b border-slate-200">
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Requested By</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Expires</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Status</th>
                        <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wider text-slate-500 bg-slate-50">Decision</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {approvals.map((a) => (
                        <tr key={a.id} className="hover:bg-slate-50/50 transition-colors">
                          <td className="px-4 py-3 text-sm font-medium text-slate-900">{a.requested_by}</td>
                          <td className="px-4 py-3 text-sm text-slate-500">{a.expires_at.slice(0, 19).replace('T', ' ')}</td>
                          <td className="px-4 py-3 text-sm">
                            <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                              a.state === 'pending' ? 'bg-amber-50 text-amber-700 border border-amber-200' :
                              a.state === 'approved' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                              'bg-red-50 text-red-700 border border-red-200'
                            }`}>
                              {a.state}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-sm text-right">
                            {a.state === 'pending' && (
                              <div className="flex items-center justify-end gap-2">
                                <button type="button" onClick={() => void review(a.id, 'approved')} className="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-emerald-700 transition-all">Approve</button>
                                <button type="button" onClick={() => void review(a.id, 'rejected')} className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700 transition-all">Reject</button>
                              </div>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ?? Page shell ????????????????????????????????????????????????????????????????

export function CopilotPage() {
  const [tab, setTab] = useState<Tab>('sessions');

  const tabs: { id: Tab; label: string }[] = [
    { id: 'sessions', label: 'Sessions' },
    { id: 'plans', label: 'Change Plans' },
    { id: 'approvals', label: 'Approvals' },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">AI Infrastructure Copilot</h1>
          <p className="text-sm text-slate-500">
            Read-only analysis, change plan generation, and policy-checked approval workflow. All tool calls are audited.
          </p>
        </div>
      </div>
      <div className="flex gap-4 border-b border-slate-200">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`pb-2 text-sm font-medium border-b-2 transition-all ${tab === t.id ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500 hover:text-slate-800'}`}
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
