import React, { useEffect, useState } from 'react';
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
  ConfirmModal,
  primaryButtonClass,
  inputClass,
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
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
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
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
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
      const rRes = await dnsTlsApi.listRecords(projectId!, selectedZone);
      setRecords(rRes.records || []);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
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
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
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
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
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
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-line pb-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-ink">DNS & TLS Management</h2>
          <p className="text-sm text-ink-secondary">Manage DNS providers, zones, records and TLS certificate lifecycle.</p>
        </div>
      </div>

      <div className="flex gap-2 border-b border-line">
        <button
          type="button"
          onClick={() => setTab('dns')}
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${
            tab === 'dns'
              ? 'border-accent text-accent'
              : 'border-transparent text-ink-secondary hover:text-ink'
          }`}
        >
          DNS Zones & Records
        </button>
        <button
          type="button"
          onClick={() => setTab('certs')}
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${
            tab === 'certs'
              ? 'border-accent text-accent'
              : 'border-transparent text-ink-secondary hover:text-ink'
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
            <h3 className="text-base font-semibold text-ink">DNS Providers</h3>
            <form onSubmit={handleCreateProvider} className="flex flex-wrap items-end gap-3 p-4 bg-surface rounded-lg border border-line">
              <div>
                <label className="block text-xs font-medium text-ink-secondary mb-1">Provider Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Cloudflare Prod"
                  className={inputClass}
                  value={providerName}
                  onChange={(e) => setProviderName(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-ink-secondary mb-1">Type</label>
                <select
                  className={inputClass}
                  value={providerType}
                  onChange={(e) => setProviderType(e.target.value)}
                >
                  <option value="cloudflare">Cloudflare</option>
                  <option value="route53">AWS Route53</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-ink-secondary mb-1">API Token (sealed)</label>
                <input
                  type="password"
                  required
                  placeholder="API Secret Token"
                  className={inputClass}
                  value={providerToken}
                  onChange={(e) => setProviderToken(e.target.value)}
                />
              </div>
              <button type="submit" className={primaryButtonClass}>Add Provider</button>
            </form>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {providers.map((p) => (
                <div key={p.id} className="p-4 bg-surface rounded-lg border border-line flex justify-between items-start">
                  <div>
                    <h4 className="font-semibold text-ink">{p.name}</h4>
                    <p className="text-xs text-ink-muted">Type: {p.provider}</p>
                    <div className="mt-2">
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
                            await loadData();
                          } catch (err) {
                            setError(err instanceof Error ? err : new Error(String(err)));
                          }
                        },
                      });
                    }}
                    className="text-xs text-danger hover:underline"
                  >
                    Delete
                  </button>
                </div>
              ))}
            </div>
          </section>

          {/* Zones & Records Section */}
          <section className="space-y-4">
            <h3 className="text-base font-semibold text-ink">DNS Zones</h3>
            <form onSubmit={handleCreateZone} className="flex flex-wrap items-end gap-3 p-4 bg-surface rounded-lg border border-line">
              <div>
                <label className="block text-xs font-medium text-ink-secondary mb-1">Zone Domain</label>
                <input
                  type="text"
                  required
                  placeholder="example.com"
                  className={inputClass}
                  value={zoneName}
                  onChange={(e) => setZoneName(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-ink-secondary mb-1">Assigned Provider</label>
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
              </div>
              <button type="submit" className={primaryButtonClass}>Create Zone</button>
            </form>

            {zones.length === 0 ? (
              <EmptyState title="No DNS Zones">
                Add a DNS provider and create your first zone above.
              </EmptyState>
            ) : (
              <div className="space-y-4">
                <div className="flex gap-2 border-b border-line pb-2">
                  {zones.map((z) => (
                    <button
                      key={z.id}
                      type="button"
                      onClick={() => setSelectedZone(z.id)}
                      className={`px-3 py-1.5 rounded text-sm ${
                        selectedZone === z.id
                          ? 'bg-elevated font-medium text-ink'
                          : 'text-ink-secondary hover:text-ink'
                      }`}
                    >
                      {z.name}
                    </button>
                  ))}
                </div>

                {selectedZone && (
                  <div className="space-y-4">
                    <form onSubmit={handleCreateRecord} className="flex flex-wrap items-end gap-3 p-4 bg-surface rounded-lg border border-line">
                      <div>
                        <label className="block text-xs font-medium text-ink-secondary mb-1">Record Name</label>
                        <input
                          type="text"
                          required
                          placeholder="sub or @"
                          className={inputClass}
                          value={recName}
                          onChange={(e) => setRecName(e.target.value)}
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-ink-secondary mb-1">Type</label>
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
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-ink-secondary mb-1">Content</label>
                        <input
                          type="text"
                          required
                          placeholder="Target IP or text"
                          className={inputClass}
                          value={recContent}
                          onChange={(e) => setRecContent(e.target.value)}
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-ink-secondary mb-1">TTL</label>
                        <input
                          type="number"
                          className={`${inputClass} w-24`}
                          value={recTTL}
                          onChange={(e) => setRecTTL(Number(e.target.value))}
                        />
                      </div>
                      <button type="submit" className={primaryButtonClass}>Add Record</button>
                    </form>

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
                                          const res = await dnsTlsApi.listRecords(projectId!, selectedZone);
                                          setRecords(res.records || []);
                                        } catch (err) {
                                          setError(err instanceof Error ? err : new Error(String(err)));
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
                                      await loadData();
                                    } catch (err) {
                                      setError(err instanceof Error ? err : new Error(String(err)));
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
            <h3 className="text-base font-semibold text-ink">Certificate Inventory</h3>
            {certificates.length === 0 ? (
              <EmptyState title="No Certificates">
                No active certificates yet. Issue a free Let's Encrypt certificate or import a custom one above.
              </EmptyState>
            ) : (
              <div className="overflow-x-auto border border-line rounded-lg">
                <table className="w-full text-left text-sm">
                  <thead className="bg-surface text-ink-muted text-xs uppercase border-b border-line">
                    <tr>
                      <th className="px-4 py-2">Domains</th>
                      <th className="px-4 py-2">Issuer</th>
                      <th className="px-4 py-2">Valid Until</th>
                      <th className="px-4 py-2">Status</th>
                      <th className="px-4 py-2">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {certificates.map((c) => (
                      <tr key={c.id}>
                        <td className="px-4 py-2 font-mono text-xs">{c.identifiers ? c.identifiers.join(', ') : 'unknown'}</td>
                        <td className="px-4 py-2">{c.issuer}</td>
                        <td className="px-4 py-2 font-mono text-xs">{new Date(c.not_after).toLocaleDateString()}</td>
                        <td className="px-4 py-2">
                          <StatusBadge
                            state={c.state === 'active' ? 'Healthy' : c.state === 'expiring' ? 'Degraded' : 'Failed'}
                            detail={c.state}
                          />
                        </td>
                        <td className="px-4 py-2">
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
                                      await loadData();
                                    } catch (err) {
                                      setError(err instanceof Error ? err : new Error(String(err)));
                                    }
                                  },
                                });
                              }}
                              className="text-xs text-danger hover:underline"
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
            )}
          </section>
        </div>
      )}
    </div>
  );
}

