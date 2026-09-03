/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Empty string means same-origin (dev proxy). */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
