import React, { useEffect, useState } from 'react';
import { goeyToast } from 'goey-toast';
import {
  dnsTlsApi,
  type CertOrder,
  type DNSProvider,
  type DNSZone,
  type DNSRecord,
  type Certificate,
} from '../api/client';
import {
  EmptyState,
  ErrorNote,
  StatusBadge,
  Modal,
  ConfirmModal,
  primaryButtonClass,
  secondaryButtonClass,
  inputClass,
  Field,
} from '../components/ui';
import { useFirstProjectId } from '../hooks/useFirstProjectId';

export function DNSTLSPage() {
  const projectId = useFirstProjectId();
  const [tab, setTab] = useState<'dns' | 'certs'>('dns');

  // DNS State
  const [providers, setProviders] = useState<DNSProvider[]>([]);
  const [zones, setZones] = useState<DNSZone[]>([]);
  const [selectedZone, setSelectedZone] = useState<string | null>(null);
  const [records, setRecords] = useState<DNSRecord[]>([]);

  // Certs State
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [orders, setOrders] = useState<CertOrder[]>([]);

  // Forms & Error
  const [error, setError] = useState<Error | null>(null);

  // Modal open states
  const [isProviderOpen, setIsProviderOpen] = useState(false);
  const [isZoneOpen, setIsZoneOpen] = useState(false);
  const [isRecordOpen, setIsRecordOpen] = useState(false);

  // New Provider Form
  const [providerName, setProviderName] = useState('');
  const [providerType, setProviderType] = useState('cloudflare');
  const [providerToken, setProviderToken] = useState('');

  // New Zone Form
  const [zoneName, setZoneName] = useState('');
  const [zoneProviderId, setZoneProviderId] = useState('');

  // New Record Form
  const [recName, setRecName] = useState('');
  const [recType, setRecType] = useState('A');
  const [recContent, setRecContent] = useState('');
  const [recTTL, setRecTTL] = useState(300);

  // Import Cert Form
  const [chainPEM, setChainPEM] = useState('');
  const [privKeyPEM, setPrivKeyPEM] = useState('');
  const [showImport, setShowImport] = useState(false);

  // ACME Order Form
  const [orderDomains, setOrderDomains] = useState('');
  const [challengeType, setChallengeType] = useState<'http-01' | 'dns-01'>('http-01');
  const [orderBusy, setOrderBusy] = useState(false);

  // Confirm modal for destructive actions
  const [confirmState, setConfirmState] = useState<{ open: boolean; message: string; onConfirm: () => void }>({ open: false, message: '', onConfirm: () => {} });

  const loadData = async () => {
    if (!projectId) return;
    setError(null);
    try {
      if (tab === 'dns') {
        const [pRes, zRes] = await Promise.all([
          dnsTlsApi.listProviders(projectId!),
          dnsTlsApi.listZones(projectId!),
        ]);
        setProviders(pRes.providers || []);
        setZones(zRes.zones || []);
        if (zRes.zones && zRes.zones.length > 0 && !selectedZone) {
          setSelectedZone(zRes.zones[0].id);
        }
      } else {
        const [cRes, oRes] = await Promise.all([
          dnsTlsApi.listCertificates(projectId!),
          dnsTlsApi.listOrders(projectId!),
        ]);
        setCertificates(cRes.certificates || []);
        setOrders(oRes.orders || []);
      }
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  };

  useEffect(() => {
    void loadData();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId, tab]);

  useEffect(() => {
    if (selectedZone && tab === 'dns') {
      void (async () => {
        try {
          const rRes = await dnsTlsApi.listRecords(projectId!, selectedZone);
          setRecords(rRes.records || []);
        } catch (err) {
          setError(err instanceof Error ? err : new Error(String(err)));
        }
      })();
    } else {
      setRecords([]);
    }
  }, [selectedZone, tab, projectId]);

  const handleCreateProvider = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await dnsTlsApi.createProvider(projectId!, {
        name: providerName,
        provider: providerType,
        token: providerToken,
      });
      setProviderName('');
      setProviderToken('');
      setIsProviderOpen(false);
      goeyToast.success('DNS provider created');
      await loadData();
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      goeyToast.error(`Failed: ${e.message}`);
      setError(e);
    }
  };

  const handleCreateZone = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await dnsTlsApi.createZone(projectId!, {
        name: zoneName,
        provider_id: zoneProviderId,
      });
      setZoneName('');
      setIsZoneOpen(false);
      goeyToast.success('DNS zone created');
      await loadData();
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      goeyToast.error(`Failed: ${e.message}`);
      setError(e);
    }
  };

  const handleCreateRecord = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedZone) return;
    try {
      await dnsTlsApi.createRecord(projectId!, selectedZone, {
        name: recName,
        type: recType,
        content: recContent,
        ttl: recTTL,
      });
      setRecName('');
      setRecContent('');
      setIsRecordOpen(false);
      goeyToast.success('DNS record created');
      const rRes = await dnsTlsApi.listRecords(projectId!, selectedZone);
      setRecords(rRes.records || []);
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      goeyToast.error(`Failed: ${e.message}`);
      setError(e);
    }
  };

  const handleImportCert = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await dnsTlsApi.importCertificate(projectId!, {
        chain_pem: chainPEM,
        private_key_pem: privKeyPEM,
      });
      setChainPEM('');
      setPrivKeyPEM('');
      setShowImport(false);
      goeyToast.success('Certificate imported');
      await loadData();
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      goeyToast.error(`Failed: ${e.message}`);
      setError(e);
    }
  };

  const handleCreateOrder = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!projectId || !orderDomains.trim()) return;
    setOrderBusy(true);
    try {
      const identifiers = orderDomains.split(',').map((d) => d.trim()).filter(Boolean);
      await dnsTlsApi.createOrder(projectId!, { identifiers });
      setOrderDomains('');
      goeyToast.success('Certificate order created');
      await loadData();
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      goeyToast.error(`Failed: ${e.message}`);
      setError(e);
    } finally {
      setOrderBusy(false);
    }
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
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">DNS &amp; TLS Management</h1>
          <p className="text-sm text-slate-500">Manage DNS providers, zones, records and TLS certificate lifecycle.</p>
        </div>
      </div>

      <div className="flex overflow-x-auto border-b border-slate-200 gap-1 pb-px">
        <button
          type="button"
          onClick={() => setTab('dns')}
          className={`px-3.5 py-2 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
            tab === 'dns'
              ? 'border-indigo-600 text-indigo-600 bg-indigo-50/50 rounded-t-md'
              : 'border-transparent text-slate-600 hover:text-slate-900 hover:border-slate-300'
          }`}
        >
          DNS Zones &amp; Records
        </button>
        <button
          type="button"
          onClick={() => setTab('certs')}
          className={`px-3.5 py-2 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
            tab === 'certs'
              ? 'border-indigo-600 text-indigo-600 bg-indigo-50/50 rounded-t-md'
              : 'border-transparent text-slate-600 hover:text-slate-900 hover:border-slate-300'
          }`}
        >
          TLS Certificates
        </button>
      </div>

      {error && <ErrorNote error={error} title="DNS/TLS Operation Error" />}

      {tab === 'dns' ? (
        <div className="space-y-8">
          {/* Providers Section */}
          <section className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-semibold text-slate-900">DNS Providers</h3>
                <p className="text-xs text-slate-500">Connected upstream authoritative DNS providers.</p>
              </div>
              <button
                type="button"
                onClick={() => setIsProviderOpen(true)}
                className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
              >
                + Add Provider
              </button>
            </div>

            <Modal
              isOpen={isProviderOpen}
              onClose={() => setIsProviderOpen(false)}
              title="Add DNS Provider"
            >
              <form onSubmit={handleCreateProvider} className="space-y-4">
                <Field label="Provider Name">
                  <input
                    type="text"
                    required
                    placeholder="e.g. Cloudflare Prod"
                    className={inputClass}
                    value={providerName}
                    onChange={(e) => setProviderName(e.target.value)}
                  />
                </Field>
                <Field label="Type">
                  <select
                    className={inputClass}
                    value={providerType}
                    onChange={(e) => setProviderType(e.target.value)}
                  >
                    <option value="cloudflare">Cloudflare</option>
                    <option value="route53">AWS Route53</option>
                  </select>
                </Field>
                <Field label="API Token (sealed)">
                  <input
                    type="password"
                    required
                    placeholder="API Secret Token"
                    className={inputClass}
                    value={providerToken}
                    onChange={(e) => setProviderToken(e.target.value)}
                  />
                </Field>
                <div className="flex justify-end gap-2 pt-2">
                  <button type="button" onClick={() => setIsProviderOpen(false)} className={secondaryButtonClass}>Cancel</button>
                  <button type="submit" className={primaryButtonClass}>Add Provider</button>
                </div>
              </form>
            </Modal>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {providers.map((p) => {
                const providerEmoji = p.provider === 'cloudflare' ? '🟧' : '🌐';
                return (
                  <div key={p.id} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm flex justify-between items-start space-y-2">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-lg" role="img" aria-label={p.provider}>{providerEmoji}</span>
                        <h4 className="font-semibold text-slate-900 text-sm">{p.name}</h4>
                      </div>
                      <p className="text-xs text-slate-500 capitalize pl-6">{p.provider}</p>
                      <div className="pt-2 pl-6">
                        <StatusBadge state={p.state === 'active' ? 'Healthy' : 'Degraded'} detail={p.state} />
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setConfirmState({
                          open: true,
                          message: `Delete DNS provider "${p.name}"? Any zones attached will lose DNS management capability.`,
                          onConfirm: async () => {
                            try {
                              await dnsTlsApi.deleteProvider(projectId!, p.id);
                              goeyToast.success('DNS provider deleted');
                              await loadData();
                            } catch (err) {
                              const e = err instanceof Error ? err : new Error(String(err));
                              goeyToast.error(`Failed: ${e.message}`);
                              setError(e);
                            }
                          },
                        });
                      }}
                      className="rounded-lg border border-slate-200 px-2.5 py-1 text-xs font-medium text-red-600 hover:bg-red-50 transition-all"
                    >
                      Delete
                    </button>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Zones & Records Section */}
          <section className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-slate-900">DNS Zones</h3>
              <button
                type="button"
                onClick={() => setIsZoneOpen(true)}
                className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
              >
                + Create Zone
              </button>
            </div>

            <Modal
              isOpen={isZoneOpen}
              onClose={() => setIsZoneOpen(false)}
              title="Create DNS Zone"
            >
              <form onSubmit={handleCreateZone} className="space-y-4">
                <Field label="Zone Domain">
                  <input
                    type="text"
                    required
                    placeholder="example.com"
                    className={inputClass}
                    value={zoneName}
                    onChange={(e) => setZoneName(e.target.value)}
                  />
                </Field>
                <Field label="Assigned Provider">
                  <select
                    required
                    className={inputClass}
                    value={zoneProviderId}
                    onChange={(e) => setZoneProviderId(e.target.value)}
                  >
                    <option value="">Select Provider...</option>
                    {providers.map((p) => (
                      <option key={p.id} value={p.id}>{p.name} ({p.provider})</option>
                    ))}
                  </select>
                </Field>
                <div className="flex justify-end gap-2 pt-2">
                  <button type="button" onClick={() => setIsZoneOpen(false)} className={secondaryButtonClass}>Cancel</button>
                  <button type="submit" className={primaryButtonClass}>Create Zone</button>
                </div>
              </form>
            </Modal>

            {zones.length === 0 ? (
              <EmptyState title="No DNS Zones">
                Add a DNS provider and create your first zone above.
              </EmptyState>
            ) : (
              <div className="space-y-4">
                <div className="flex flex-wrap gap-2">
                  {zones.map((z) => (
                    <button
                      key={z.id}
                      type="button"
                      onClick={() => setSelectedZone(z.id)}
                      className={`rounded-lg border px-3.5 py-1.5 text-sm font-medium transition-all ${
                        selectedZone === z.id
                          ? 'border-indigo-600 bg-indigo-50 text-indigo-700 shadow-sm ring-1 ring-indigo-600'
                          : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300 hover:bg-slate-50'
                      }`}
                    >
                      {z.name}
                    </button>
                  ))}
                </div>

                {selectedZone && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h4 className="text-sm font-semibold text-ink">Zone Records</h4>
                      <button
                        type="button"
                        onClick={() => setIsRecordOpen(true)}
                        className={primaryButtonClass}
                      >
                        + Add Record
                      </button>
                    </div>

                    <Modal
                      isOpen={isRecordOpen}
                      onClose={() => setIsRecordOpen(false)}
                      title="Add DNS Record"
                    >
                      <form onSubmit={handleCreateRecord} className="space-y-4">
                        <Field label="Record Name">
                          <input
                            type="text"
                            required
                            placeholder="sub or @"
                            className={inputClass}
                            value={recName}
                            onChange={(e) => setRecName(e.target.value)}
                          />
                        </Field>
                        <Field label="Type">
                          <select
                            className={inputClass}
                            value={recType}
                            onChange={(e) => setRecType(e.target.value)}
                          >
                            <option value="A">A</option>
                            <option value="AAAA">AAAA</option>
                            <option value="CNAME">CNAME</option>
                            <option value="TXT">TXT</option>
                            <option value="MX">MX</option>
                          </select>
                        </Field>
                        <Field label="Content">
                          <input
                            type="text"
                            required
                            placeholder="Target IP or text"
                            className={inputClass}
                            value={recContent}
                            onChange={(e) => setRecContent(e.target.value)}
                          />
                        </Field>
                        <Field label="TTL">
                          <input
                            type="number"
                            className={inputClass}
                            value={recTTL}
                            onChange={(e) => setRecTTL(Number(e.target.value))}
                          />
                        </Field>
                        <div className="flex justify-end gap-2 pt-2">
                          <button type="button" onClick={() => setIsRecordOpen(false)} className={secondaryButtonClass}>Cancel</button>
                          <button type="submit" className={primaryButtonClass}>Add Record</button>
                        </div>
                      </form>
                    </Modal>

                    <div className="overflow-x-auto border border-line rounded-lg">
                      <table className="w-full text-left text-sm">
                        <thead className="bg-surface text-ink-muted text-xs uppercase border-b border-line">
                          <tr>
                            <th className="px-4 py-2">Name</th>
                            <th className="px-4 py-2">Type</th>
                            <th className="px-4 py-2">Content</th>
                            <th className="px-4 py-2">TTL</th>
                            <th className="px-4 py-2">Status</th>
                            <th className="px-4 py-2">Action</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-line">
                          {records.map((r) => (
                            <tr key={r.id}>
                              <td className="px-4 py-2 font-mono">{r.name}</td>
                              <td className="px-4 py-2 font-mono">{r.type}</td>
                              <td className="px-4 py-2 font-mono truncate max-w-xs">{r.content}</td>
                              <td className="px-4 py-2">{r.ttl}</td>
                              <td className="px-4 py-2">
                                <StatusBadge state={r.state === 'synced' ? 'Healthy' : 'Degraded'} detail={r.state} />
                              </td>
                              <td className="px-4 py-2">
                                <button
                                  type="button"
                                  onClick={() => {
                                    setConfirmState({
                                      open: true,
                                      message: `Delete DNS record "${r.name} (${r.type})"? This cannot be undone.`,
                                      onConfirm: async () => {
                                        try {
                                          await dnsTlsApi.deleteRecord(projectId!, selectedZone, r.id);
                                          goeyToast.success('DNS record deleted');
                                          const res = await dnsTlsApi.listRecords(projectId!, selectedZone);
                                          setRecords(res.records || []);
                                        } catch (err) {
                                          const e = err instanceof Error ? err : new Error(String(err));
                                          goeyToast.error(`Failed: ${e.message}`);
                                          setError(e);
                                        }
                                      },
                                    });
                                  }}
                                  className="text-xs text-danger hover:underline"
                                >
                                  Delete
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )}
          </section>
        </div>
      ) : (
        <div className="space-y-8">
          {/* Option 1: Free SSL via Let's Encrypt */}
          <section className="rounded-xl border border-line bg-surface p-5 space-y-4">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-base font-semibold text-ink flex items-center gap-2">
                  <span className="inline-flex items-center rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700">FREE</span>
                  Let's Encrypt / ACME Auto-Issue
                </h3>
                <p className="text-xs text-ink-muted mt-1">Get a free, auto-renewing SSL certificate. Works for single domains and multi-domain (SAN) certs. Wildcard (*.example.com) requires DNS API provider configured first.</p>
              </div>
            </div>
            <form onSubmit={handleCreateOrder} className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-ink-secondary mb-2">Verification Method</label>
                <div className="flex gap-3">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="challengeType"
                      value="http-01"
                      checked={challengeType === 'http-01'}
                      onChange={() => setChallengeType('http-01')}
                      className="accent-indigo-600"
                    />
                    <span className="text-sm text-ink">HTTP-01 <span className="text-ink-muted">(standard, requires port 80 open)</span></span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="challengeType"
                      value="dns-01"
                      checked={challengeType === 'dns-01'}
                      onChange={() => setChallengeType('dns-01')}
                      className="accent-indigo-600"
                    />
                    <span className="text-sm text-ink">DNS-01 <span className="text-ink-muted">(wildcard support, uses DNS provider)</span></span>
                  </label>
                </div>
                {challengeType === 'dns-01' && providers.length === 0 && (
                  <p className="text-xs text-amber-600 mt-1">No DNS provider configured. Add a provider in the DNS tab first for DNS-01 challenges.</p>
                )}
              </div>
              <div>
                <label className="block text-xs font-medium text-ink-secondary mb-1">Domain Name(s)</label>
                <input
                  className={inputClass}
                  value={orderDomains}
                  onChange={(e) => setOrderDomains(e.target.value)}
                  placeholder={challengeType === 'dns-01' ? '*.example.com, example.com' : 'example.com, www.example.com'}
                  required
                />
                <p className="text-xs text-ink-muted mt-1">Separate multiple domains with commas.{challengeType === 'dns-01' ? ' Wildcard ' : ' '}<span className="font-mono">{challengeType === 'dns-01' ? '*.example.com' : 'www.example.com'}</span> supported.</p>
              </div>
              <button type="submit" className={primaryButtonClass} disabled={orderBusy}>
                {orderBusy ? 'Requesting...' : 'Issue Free SSL Certificate'}
              </button>
            </form>
          </section>

          {/* ACME Orders Status */}
          {orders.length > 0 && (
            <section className="space-y-3">
              <h3 className="text-sm font-semibold text-ink">Certificate Orders</h3>
              <div className="overflow-x-auto border border-line rounded-lg">
                <table className="w-full text-left text-sm">
                  <thead className="bg-surface text-ink-muted text-xs uppercase border-b border-line">
                    <tr>
                      <th className="px-4 py-2">Domains</th>
                      <th className="px-4 py-2">Status</th>
                      <th className="px-4 py-2">Requested</th>
                      <th className="px-4 py-2">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {orders.map((o) => (
                      <tr key={o.id}>
                        <td className="px-4 py-2 font-mono text-xs">{(o.identifiers || []).join(', ')}</td>
                        <td className="px-4 py-2">
                          <StatusBadge
                            state={o.state === 'valid' ? 'Healthy' : o.state === 'pending' || o.state === 'processing' ? 'Pending' : o.state === 'canceled' ? 'Paused' : 'Failed'}
                            detail={o.state}
                          />
                        </td>
                        <td className="px-4 py-2 text-xs text-ink-muted">{new Date(o.created_at).toLocaleString()}</td>
                        <td className="px-4 py-2">
                          {(o.state === 'pending' || o.state === 'processing') && (
                            <button
                              type="button"
                              onClick={() => {
                                setConfirmState({
                                  open: true,
                                  message: `Cancel certificate order for ${(o.identifiers || []).join(', ')}?`,
                                  onConfirm: async () => {
                                    try {
                                      await dnsTlsApi.cancelOrder(projectId!, o.id);
                                      goeyToast.success('Order cancelled');
                                      await loadData();
                                    } catch (err) {
                                      const e = err instanceof Error ? err : new Error(String(err));
                                      goeyToast.error(`Failed: ${e.message}`);
                                      setError(e);
                                    }
                                  },
                                });
                              }}
                              className="text-xs text-danger hover:underline"
                            >
                              Cancel
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* Option 2: Custom Certificate Import */}
          <section className="rounded-xl border border-line bg-surface p-5 space-y-4">
            <div>
              <h3 className="text-base font-semibold text-ink">Custom / Paid Certificate</h3>
              <p className="text-xs text-ink-muted mt-1">Import a certificate from Sectigo, DigiCert, Cloudflare Origin CA, or any other CA. Paste PEM-format chain and private key.</p>
            </div>
            {!showImport ? (
              <button type="button" onClick={() => setShowImport(true)} className="text-sm text-accent hover:underline">
                + Upload certificate (PEM)
              </button>
            ) : (
              <form onSubmit={handleImportCert} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-ink-secondary mb-1">Certificate Chain (PEM)</label>
                  <textarea required rows={4} placeholder="-----BEGIN CERTIFICATE-----..." className={`${inputClass} font-mono text-xs`} value={chainPEM} onChange={(e) => setChainPEM(e.target.value)} />
                </div>
                <div>
                  <label className="block text-xs font-medium text-ink-secondary mb-1">Private Key (PEM)</label>
                  <textarea required rows={4} placeholder="-----BEGIN PRIVATE KEY-----..." className={`${inputClass} font-mono text-xs`} value={privKeyPEM} onChange={(e) => setPrivKeyPEM(e.target.value)} />
                </div>
                <div className="flex gap-2">
                  <button type="submit" className={primaryButtonClass}>Import Certificate</button>
                  <button type="button" onClick={() => setShowImport(false)} className="text-sm text-ink-muted hover:text-ink">Cancel</button>
                </div>
              </form>
            )}
          </section>

          {/* Certificate Inventory */}
          <section className="space-y-4">
            <h3 className="text-base font-semibold text-slate-900">Certificate Inventory</h3>
            {certificates.length === 0 ? (
              <EmptyState title="No Certificates">
                No active certificates yet. Issue a free Let's Encrypt certificate or import a custom one above.
              </EmptyState>
            ) : (
              <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-50 text-slate-500 text-xs uppercase tracking-wider border-b border-slate-200">
                    <tr>
                      <th className="px-4 py-3">Domains</th>
                      <th className="px-4 py-3">Issuer</th>
                      <th className="px-4 py-3">Valid Until</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {certificates.map((c) => {
                      const daysUntilExpiry = c.not_after
                        ? Math.ceil((new Date(c.not_after).getTime() - Date.now()) / 86400000)
                        : null;
                      const expiryBadge =
                        c.state === 'revoked'
                          ? 'rounded-full bg-red-50 border border-red-200 px-2.5 py-0.5 text-xs font-medium text-red-700'
                          : c.state === 'expiring' || (daysUntilExpiry !== null && daysUntilExpiry <= 30)
                          ? 'rounded-full bg-amber-50 border border-amber-200 px-2.5 py-0.5 text-xs font-medium text-amber-700'
                          : 'rounded-full bg-emerald-50 border border-emerald-200 px-2.5 py-0.5 text-xs font-medium text-emerald-700';
                      const expiryLabel =
                        c.state === 'revoked'
                          ? 'Revoked'
                          : c.state === 'expiring'
                          ? `Expiring in ${daysUntilExpiry ?? '?'}d`
                          : 'Valid';
                      return (
                        <tr key={c.id} className="hover:bg-slate-50/50 transition-colors">
                          <td className="px-4 py-3 font-mono text-xs text-slate-900">{c.identifiers ? c.identifiers.join(', ') : 'unknown'}</td>
                          <td className="px-4 py-3 text-xs text-slate-700">{c.issuer}</td>
                          <td className="px-4 py-3 font-mono text-xs text-slate-700">{new Date(c.not_after).toLocaleDateString()}</td>
                          <td className="px-4 py-3">
                            <span className={expiryBadge}>{expiryLabel}</span>
                          </td>
                          <td className="px-4 py-3">
                            {c.state !== 'revoked' && (
                              <button
                                type="button"
                                onClick={() => {
                                  setConfirmState({
                                    open: true,
                                    message: `Revoke certificate for ${c.identifiers ? c.identifiers.join(', ') : 'this domain'}? This certificate will become invalid immediately.`,
                                    onConfirm: async () => {
                                      try {
                                        await dnsTlsApi.revokeCertificate(projectId!, c.id, 'operator manual revocation');
                                        goeyToast.success('Certificate revoked');
                                        await loadData();
                                      } catch (err) {
                                        const e = err instanceof Error ? err : new Error(String(err));
                                        goeyToast.error(`Failed: ${e.message}`);
                                        setError(e);
                                      }
                                    },
                                  });
                                }}
                                className="rounded-lg border border-slate-200 px-2.5 py-1 text-xs font-medium text-red-600 hover:bg-red-50 transition-all"
                              >
                                Revoke
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}

