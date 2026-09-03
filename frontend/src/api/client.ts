/**
 * Central HTTP client for the Nexus One API.
 *
 * The backend URL is configured through VITE_API_BASE_URL (see
 * frontend/.env.example). When it is empty the app uses same-origin requests,
 * which the Vite dev-server proxy forwards to the backend.
 */

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/+$/, '');

export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(message: string, status = 0, detail?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

export function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
}

function extractMessage(status: number, statusText: string, body: unknown): string {
  if (body && typeof body === 'object' && 'detail' in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === 'string' && detail.length > 0) return detail;
    if (detail && typeof detail === 'object') {
      const msg = (detail as { message?: unknown }).message;
      if (typeof msg === 'string' && msg.length > 0) return msg;
      return JSON.stringify(detail);
    }
  }
  return `Request failed (${status}${statusText ? ` ${statusText}` : ''})`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(apiUrl(path), {
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      ...init,
    });
  } catch {
    throw new ApiError(
      'Cannot reach the Nexus One API. Check that the backend is running.',
      0,
    );
  }

  if (!response.ok) {
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    throw new ApiError(
      extractMessage(response.status, response.statusText, body),
      response.status,
      body,
    );
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

async function requestText(path: string, init?: RequestInit): Promise<string> {
  let response: Response;
  try {
    response = await fetch(apiUrl(path), {
      headers: { Accept: 'text/html' },
      ...init,
    });
  } catch {
    throw new ApiError(
      'Cannot reach the Nexus One API. Check that the backend is running.',
      0,
    );
  }
  if (!response.ok) {
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    throw new ApiError(
      extractMessage(response.status, response.statusText, body),
      response.status,
      body,
    );
  }
  return response.text();
}

async function requestBlob(path: string, init?: RequestInit): Promise<Blob> {
  let response: Response;
  try {
    response = await fetch(apiUrl(path), {
      headers: { Accept: 'application/pdf' },
      ...init,
    });
  } catch {
    throw new ApiError(
      'Cannot reach the Nexus One API. Check that the backend is running.',
      0,
    );
  }
  if (!response.ok) {
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    throw new ApiError(
      extractMessage(response.status, response.statusText, body),
      response.status,
      body,
    );
  }
  return response.blob();
}

export const http = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: 'POST',
      body: JSON.stringify(body ?? {}),
    }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: 'PATCH',
      body: JSON.stringify(body ?? {}),
    }),
  getText: (path: string) => requestText(path),
  postText: (path: string) => requestText(path, { method: 'POST' }),
  getBlob: (path: string) => requestBlob(path),
};
