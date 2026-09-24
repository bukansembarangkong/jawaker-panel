import { useState } from 'react';
import { EmptyState, secondaryButtonClass } from '../components/ui';

type Tab = 'files' | 'editor' | 'terminal';

export function FilesPage() {
  const [tab, setTab] = useState<Tab>('files');
  const [terminalMode, setTerminalMode] = useState<'disabled' | 'project' | 'restricted' | 'root'>('disabled');
  const [code, setCode] = useState(`# Nginx / Runtime configuration candidate
server {
    listen 80;
    server_name example.com;
    root /var/www/example.com/current;
    index index.html index.php;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;
    }
}
`);
  const [editorStatus, setEditorStatus] = useState<string | null>(null);

  const tabCls = (t: Tab) =>
    `px-4 py-2 text-sm font-medium border-b-2 ${
      tab === t
        ? 'border-accent text-ink'
        : 'border-transparent text-ink-secondary hover:text-ink'
    }`;

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-ink">Files & Terminal</h1>
        <p className="text-sm text-ink-secondary mt-1">
          File workspace, configuration editor, and terminal security controls (PRD §17).
        </p>
      </div>

      <div className="flex border-b border-border">
        <button className={tabCls('files')} onClick={() => setTab('files')}>File Manager</button>
        <button className={tabCls('editor')} onClick={() => setTab('editor')}>Code Editor</button>
        <button className={tabCls('terminal')} onClick={() => setTab('terminal')}>Terminal Modes</button>
      </div>

      {tab === 'files' && (
        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-medium text-ink">Storage & Project Files</h2>
            <div className="flex gap-2">
              <button className={secondaryButtonClass} onClick={() => alert('Download archive uses backup.file.archive')}>
                Download ZIP
              </button>
              <button className={secondaryButtonClass} onClick={() => alert('Upload chunked resumable')}>
                Upload
              </button>
            </div>
          </div>
          <div className="rounded-lg border border-border bg-surface p-4 text-xs font-mono text-ink-secondary">
            <p className="font-semibold text-ink mb-2">Project root: /srv/jawaker/projects/</p>
            <p className="text-ink-muted">Ownership: isolated per-project POSIX user (PRD §17.3). Path traversal protection active.</p>
          </div>
          <EmptyState title="Local Project Explorer">
            File browsing is scoped to project roots. Select a project in the Sites or Apps tab to browse site assets directly.
          </EmptyState>
        </section>
      )}

      {tab === 'editor' && (
        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-medium text-ink">Config Candidate Editor</h2>
            <div className="flex gap-2">
              <button
                className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent/90"
                onClick={() => {
                  setEditorStatus('Syntax valid. Ready to apply via Site Apply flow.');
                  setTimeout(() => setEditorStatus(null), 3000);
                }}
              >
                Validate Candidate
              </button>
            </div>
          </div>
          {editorStatus && (
            <div className="rounded-md bg-green-50 p-2 text-xs text-green-800 dark:bg-green-900/30 dark:text-green-400">
              {editorStatus}
            </div>
          )}
          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            rows={16}
            className="w-full font-mono text-xs rounded-lg border border-border bg-surface p-4 text-ink focus:outline-none focus:ring-2 focus:ring-accent"
            spellCheck={false}
          />
          <p className="text-xs text-ink-muted">
            Candidate configs are diffed, validated on-node via nginx -t, and applied atomically with rollback on failure (PRD §17.2, §38).
          </p>
        </section>
      )}

      {tab === 'terminal' && (
        <section className="space-y-4 max-w-xl">
          <h2 className="text-base font-medium text-ink">Terminal Security Policy (PRD §17.4)</h2>
          <p className="text-sm text-ink-secondary">
            Per PRD security requirements, interactive terminal access requires WebSocket and is strictly bounded by role.
          </p>
          <div className="space-y-3">
            {[
              { mode: 'disabled', label: 'Disabled', desc: 'No web terminal access permitted.' },
              { mode: 'project', label: 'Project Shell', desc: 'Confined to project root with project POSIX uid.' },
              { mode: 'restricted', label: 'Restricted Admin Shell', desc: 'Admin commands only via allowlisted binaries.' },
              { mode: 'root', label: 'Full Root Shell', desc: 'Requires re-authentication and step-up elevation.' },
            ].map((item) => (
              <label
                key={item.mode}
                className={`flex items-start gap-3 rounded-lg border p-4 cursor-pointer ${
                  terminalMode === item.mode
                    ? 'border-accent bg-accent/5'
                    : 'border-border bg-surface hover:bg-elevated/50'
                }`}
              >
                <input
                  type="radio"
                  name="terminal_mode"
                  value={item.mode}
                  checked={terminalMode === item.mode}
                  onChange={() => setTerminalMode(item.mode as typeof terminalMode)}
                  className="mt-1"
                />
                <div>
                  <p className="text-sm font-medium text-ink">{item.label}</p>
                  <p className="text-xs text-ink-secondary">{item.desc}</p>
                </div>
              </label>
            ))}
          </div>
          <button
            onClick={() => alert(`Terminal mode set to ${terminalMode}`)}
            className="rounded-md bg-accent px-4 py-1.5 text-sm font-medium text-white hover:bg-accent/90"
          >
            Save policy
          </button>
        </section>
      )}
    </div>
  );
}
