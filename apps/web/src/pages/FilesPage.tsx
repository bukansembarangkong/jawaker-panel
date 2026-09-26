export function FilesPage() {
  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Files & Terminal</h1>
          <p className="text-sm text-slate-500">
            Project workspace explorer, configuration editor, and host terminal controls.
          </p>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-50 px-3 py-1 text-xs font-medium text-amber-700 border border-amber-200 w-fit">
          <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
          Coming Soon
        </span>
      </div>

      {/* Polished Placeholder Card */}
      <div className="rounded-xl border border-slate-200 bg-white p-12 shadow-sm text-center">
        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-indigo-50 text-3xl">
          📂
        </div>
        <h2 className="mt-4 text-lg font-bold text-slate-900">File Manager & Web Terminal Under Construction</h2>
        <p className="mx-auto mt-2 max-w-lg text-sm text-slate-500 leading-relaxed">
          Integrated file management, atomic in-browser candidate editing, and sandboxed web terminal controls
          are being developed for an upcoming release. In the meantime, use your site repositories or direct SSH access.
        </p>

        <div className="mt-6 flex flex-wrap justify-center gap-3">
          <a
            href="#/sites"
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 active:scale-95 transition-all"
          >
            Manage Sites & Deployments →
          </a>
          <a
            href="#/databases"
            className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 active:scale-95 transition-all"
          >
            Browse Databases →
          </a>
        </div>
      </div>
    </div>
  );
}
