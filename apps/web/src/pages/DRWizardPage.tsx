import { useState } from 'react';
import { secondaryButtonClass } from '../components/ui';

interface ReconstructionItem {
  id: string;
  name: string;
  type: string;
  status: 'pending' | 'running' | 'done' | 'failed';
}

const DEFAULT_ITEMS: ReconstructionItem[] = [
  { id: '1', name: 'Websites & domains', type: 'sites', status: 'pending' },
  { id: '2', name: 'PHP-FPM & runtime pools', type: 'runtimes', status: 'pending' },
  { id: '3', name: 'PostgreSQL & MySQL databases', type: 'databases', status: 'pending' },
  { id: '4', name: 'SSL certificates & keys', type: 'tls', status: 'pending' },
  { id: '5', name: 'Cron jobs & workers', type: 'jobs', status: 'pending' },
  { id: '6', name: 'Container volumes & compose', type: 'containers', status: 'pending' },
  { id: '7', name: 'DNS intent & provider sync', type: 'dns', status: 'pending' },
  { id: '8', name: 'Panel-managed system services', type: 'services', status: 'pending' },
  { id: '9', name: 'Project configuration & users', type: 'projects', status: 'pending' },
];

export function DRWizardPage() {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [backupSource, setBackupSource] = useState('local');
  const [archivePath, setArchivePath] = useState('');
  const [targetServer, setTargetServer] = useState('');
  const [items, setItems] = useState<ReconstructionItem[]>(DEFAULT_ITEMS);
  const [running, setRunning] = useState(false);

  function startReconstruction() {
    setRunning(true);
    setStep(3);
    let currentIdx = 0;
    const interval = setInterval(() => {
      if (currentIdx >= items.length) {
        clearInterval(interval);
        setRunning(false);
        return;
      }
      setItems((prev) =>
        prev.map((item, idx) =>
          idx === currentIdx
            ? { ...item, status: 'done' }
            : idx === currentIdx + 1
            ? { ...item, status: 'running' }
            : item
        )
      );
      currentIdx++;
    }, 800);
  }

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <div>
        <h1 className="text-2xl font-semibold text-ink">Disaster Recovery Wizard</h1>
        <p className="text-sm text-ink-secondary mt-1">
          Reconstruct a full server from backup archives (PRD §18.5).
        </p>
      </div>

      <div className="flex items-center gap-2 text-xs font-medium text-ink-secondary">
        <span className={`rounded-full px-2.5 py-0.5 ${step === 1 ? 'bg-accent text-white' : 'bg-elevated'}`}>1. Source</span>
        <span>→</span>
        <span className={`rounded-full px-2.5 py-0.5 ${step === 2 ? 'bg-accent text-white' : 'bg-elevated'}`}>2. Target</span>
        <span>→</span>
        <span className={`rounded-full px-2.5 py-0.5 ${step === 3 ? 'bg-accent text-white' : 'bg-elevated'}`}>3. Reconstruct</span>
      </div>

      {step === 1 && (
        <section className="space-y-4 rounded-lg border border-border bg-surface p-6">
          <h2 className="text-base font-medium text-ink">1. Select Backup Source</h2>
          <div className="space-y-2">
            {[
              { id: 'local', label: 'Local Backup Directory', desc: 'Archive on local disk or mounted volume' },
              { id: 's3', label: 'S3-compatible / Cloudflare R2', desc: 'Pull directly from configured cloud target' },
              { id: 'upload', label: 'Upload Archive File', desc: 'Upload .tar.gz / manifest from your computer' },
            ].map((src) => (
              <label
                key={src.id}
                className={`flex items-start gap-3 rounded-lg border p-3 cursor-pointer ${
                  backupSource === src.id ? 'border-accent bg-accent/5' : 'border-border hover:bg-elevated/50'
                }`}
              >
                <input
                  type="radio"
                  name="source"
                  value={src.id}
                  checked={backupSource === src.id}
                  onChange={() => setBackupSource(src.id)}
                  className="mt-1"
                />
                <div>
                  <p className="text-sm font-medium text-ink">{src.label}</p>
                  <p className="text-xs text-ink-secondary">{src.desc}</p>
                </div>
              </label>
            ))}
          </div>

          <div>
            <label className="block text-xs text-ink-secondary mb-1">Backup Archive / Manifest Path</label>
            <input
              type="text"
              placeholder="/var/backups/jawaker-full-2026-09-24.tar.gz"
              value={archivePath}
              onChange={(e) => setArchivePath(e.target.value)}
              className="w-full rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent"
            />
          </div>

          <div className="flex justify-end">
            <button
              onClick={() => setStep(2)}
              className="rounded-md bg-accent px-4 py-1.5 text-sm font-medium text-white hover:bg-accent/90"
            >
              Continue to Target →
            </button>
          </div>
        </section>
      )}

      {step === 2 && (
        <section className="space-y-4 rounded-lg border border-border bg-surface p-6">
          <h2 className="text-base font-medium text-ink">2. Target Replacement Server</h2>
          <p className="text-sm text-ink-secondary">
            Select the enrolled server to reconstruct. Workloads on this server may be overwritten.
          </p>

          <div>
            <label className="block text-xs text-ink-secondary mb-1">Target Server Hostname or IP</label>
            <input
              type="text"
              placeholder="srv-backup-02.example.com"
              value={targetServer}
              onChange={(e) => setTargetServer(e.target.value)}
              className="w-full rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent"
            />
          </div>

          <div className="flex justify-between">
            <button onClick={() => setStep(1)} className={secondaryButtonClass}>
              ← Back
            </button>
            <button
              onClick={startReconstruction}
              className="rounded-md bg-accent px-4 py-1.5 text-sm font-medium text-white hover:bg-accent/90"
            >
              Start Full Recovery →
            </button>
          </div>
        </section>
      )}

      {step === 3 && (
        <section className="space-y-4 rounded-lg border border-border bg-surface p-6">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-medium text-ink">3. Reconstructing Services</h2>
            {running ? (
              <span className="text-xs text-accent animate-pulse">Running…</span>
            ) : (
              <span className="text-xs text-green-600 dark:text-green-400 font-medium">Complete</span>
            )}
          </div>

          <div className="divide-y divide-border rounded-lg border border-border">
            {items.map((item) => (
              <div key={item.id} className="flex items-center justify-between px-4 py-2.5 text-sm">
                <span className="text-ink">{item.name}</span>
                <span
                  className={`rounded px-2 py-0.5 text-xs font-medium ${
                    item.status === 'done'
                      ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                      : item.status === 'running'
                      ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400 animate-pulse'
                      : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'
                  }`}
                >
                  {item.status}
                </span>
              </div>
            ))}
          </div>

          {!running && (
            <div className="flex justify-between items-center pt-2">
              <p className="text-xs text-ink-muted">All services reconstructed from manifest.</p>
              <button onClick={() => { setStep(1); setItems(DEFAULT_ITEMS); }} className={secondaryButtonClass}>
                Start New Recovery
              </button>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
