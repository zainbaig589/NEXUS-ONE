import { vi } from 'vitest';

export type MockRoute = {
  status?: number;
  body?: unknown;
  text?: string;
  /** Restrict the route to one HTTP method; omit to match any method. */
  method?: string;
};
export type RouteTable = Record<string, MockRoute>;

function respond(route: MockRoute | undefined, href: string, method: string): Response {
  const resolved = route ?? { status: 404, body: { detail: `No mock for ${method} ${href}` } };
  const isText = resolved.text !== undefined;
  const body = isText ? (resolved.text as string) : JSON.stringify(resolved.body ?? {});
  return new Response(body, {
    status: resolved.status ?? 200,
    headers: { 'Content-Type': isText ? 'text/html' : 'application/json' },
  });
}

/**
 * Install a global fetch mock backed by a longest-prefix URL route table.
 * Routes may pin an HTTP method; un-pinned routes match any method, but a
 * method-specific route always wins over a generic one for the same URL.
 */
export function installFetchMock(routes: RouteTable = {}): {
  mock: ReturnType<typeof vi.fn>;
  setRoutes: (next: RouteTable) => void;
} {
  const table: { current: RouteTable } = { current: routes };

  function lookup(href: string, method: string): MockRoute | undefined {
    let generic: MockRoute | undefined;
    let genericLen = -1;
    let specific: MockRoute | undefined;
    let specificLen = -1;
    for (const [prefix, route] of Object.entries(table.current)) {
      if (!href.includes(prefix)) continue;
      const methodMatches = !route.method || route.method.toUpperCase() === method;
      if (!methodMatches) continue;
      if (route.method) {
        if (prefix.length > specificLen) {
          specific = route;
          specificLen = prefix.length;
        }
      } else if (prefix.length > genericLen) {
        generic = route;
        genericLen = prefix.length;
      }
    }
    return specific ?? generic;
  }

  const mock = vi.fn(async (url: string | URL, init?: RequestInit) => {
    const href = url.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    return respond(lookup(href, method), href, method);
  });

  vi.stubGlobal('fetch', mock);

  return {
    mock,
    setRoutes: (next: RouteTable) => {
      table.current = next;
    },
  };
}

/** Simulate total network failure (backend unreachable). */
export function failFetch(): void {
  vi.stubGlobal('fetch', vi.fn(async () => {
    throw new TypeError('Failed to fetch');
  }));
}
