import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vitest/config';

const here = dirname(fileURLToPath(import.meta.url));

// Version comes from the repository root VERSION file so binaries and UI
// always report the same identity (Phase 0 gate: consistent version
// injection). Fallback keeps `vite dev` working if the file is missing.
function readRepoVersion(): string {
  try {
    return readFileSync(resolve(here, '../../VERSION'), 'utf8').trim();
  } catch {
    return '0.0.0-dev';
  }
}

// Controller address for the dev proxy. Override when the controller binds
// elsewhere: JAWAKER_DEV_PROXY=http://127.0.0.1:9000 npm run dev
const devProxyTarget = process.env.JAWAKER_DEV_PROXY ?? 'http://127.0.0.1:8443';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  define: {
    __JAWAKER_VERSION__: JSON.stringify(readRepoVersion()),
  },
  server: {
    // Loopback only: the dev server must not expose the panel API.
    host: '127.0.0.1',
    proxy: {
      '/api': { target: devProxyTarget, changeOrigin: true },
      '/healthz': { target: devProxyTarget, changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
  },
});
