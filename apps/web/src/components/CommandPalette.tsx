import { useEffect, useState } from 'react';

interface PaletteItem {
  id: string;
  category: string;
  label: string;
  hash: string;
}

const ITEMS: PaletteItem[] = [
  { id: 'dash', category: 'Navigation', label: 'Dashboard', hash: '#/' },
  { id: 'servers', category: 'Navigation', label: 'Servers', hash: '#/servers' },
  { id: 'sites', category: 'Navigation', label: 'Sites', hash: '#/sites' },
  { id: 'apps', category: 'Navigation', label: 'Applications', hash: '#/apps' },
  { id: 'databases', category: 'Navigation', label: 'Databases', hash: '#/databases' },
  { id: 'backups', category: 'Navigation', label: 'Backups', hash: '#/backups' },
  { id: 'observability', category: 'Navigation', label: 'Observability & Metrics', hash: '#/observability' },
  { id: 'dnstls', category: 'Navigation', label: 'DNS & TLS', hash: '#/dnstls' },
  { id: 'containers', category: 'Navigation', label: 'Containers', hash: '#/containers' },
  { id: 'networking', category: 'Navigation', label: 'Networking & Firewall', hash: '#/networking' },
  { id: 'sec', category: 'Navigation', label: 'Security Center', hash: '#/security-center' },
  { id: 'updates', category: 'Navigation', label: 'Platform Updates', hash: '#/updates' },
  { id: 'mail', category: 'Navigation', label: 'Mail Platform', hash: '#/mail' },
  { id: 'ha', category: 'Navigation', label: 'High Availability', hash: '#/ha' },
  { id: 'copilot', category: 'Navigation', label: 'AI Copilot', hash: '#/copilot' },
  { id: 'plugins', category: 'Navigation', label: 'Plugins & Modules', hash: '#/plugins' },
  { id: 'hardening', category: 'Navigation', label: 'Hardening & Runbooks', hash: '#/hardening' },
  { id: 'tokens', category: 'Navigation', label: 'API Tokens', hash: '#/api-tokens' },
  { id: 'users', category: 'Navigation', label: 'Users', hash: '#/users' },
  { id: 'notifications', category: 'Navigation', label: 'Notifications', hash: '#/notifications' },
  { id: 'workers', category: 'Navigation', label: 'Workers & Jobs', hash: '#/workers' },
  { id: 'files', category: 'Navigation', label: 'Files & Terminal', hash: '#/files' },
  { id: 'settings', category: 'Navigation', label: 'Platform Settings', hash: '#/settings' },
  { id: 'dr', category: 'Navigation', label: 'Disaster Recovery Wizard', hash: '#/dr-wizard' },
];

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState('');
  const [selectedIdx, setSelectedIdx] = useState(0);

  const filtered = ITEMS.filter(
    (item) =>
      item.label.toLowerCase().includes(query.toLowerCase()) ||
      item.category.toLowerCase().includes(query.toLowerCase())
  );

  useEffect(() => {
    setSelectedIdx(0);
  }, [query]);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (!open) return;
      if (e.key === 'Escape') {
        onClose();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIdx((prev) => (prev + 1) % (filtered.length || 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIdx((prev) => (prev - 1 + filtered.length) % (filtered.length || 1));
      } else if (e.key === 'Enter' && filtered[selectedIdx]) {
        e.preventDefault();
        window.location.hash = filtered[selectedIdx].hash;
        onClose();
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, filtered, selectedIdx, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 pt-20">
      <div className="w-full max-w-lg rounded-xl border border-border bg-surface shadow-2xl overflow-hidden">
        <div className="border-b border-border p-3">
          <input
            type="text"
            autoFocus
            placeholder="Type a command or jump to page… (Esc to close)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-transparent text-sm text-ink placeholder:text-ink-muted focus:outline-none"
          />
        </div>
        <div className="max-h-80 overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <p className="p-3 text-center text-xs text-ink-secondary">No results found.</p>
          ) : (
            filtered.map((item, idx) => (
              <div
                key={item.id}
                onClick={() => {
                  window.location.hash = item.hash;
                  onClose();
                }}
                className={`flex items-center justify-between rounded-lg px-3 py-2 text-sm cursor-pointer ${
                  idx === selectedIdx ? 'bg-accent text-white' : 'text-ink hover:bg-elevated'
                }`}
              >
                <span>{item.label}</span>
                <span className={`text-xs ${idx === selectedIdx ? 'text-white/70' : 'text-ink-muted'}`}>
                  {item.category}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
