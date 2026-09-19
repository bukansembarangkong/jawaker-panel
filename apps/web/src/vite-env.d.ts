/// <reference types="vite/client" />

/**
 * Build-time version injected from the repository root VERSION file via
 * vite.config `define`. Same identity the controller binary reports.
 */
declare const __JAWAKER_VERSION__: string;
