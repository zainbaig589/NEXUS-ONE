import { useCallback, useEffect, useRef, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';

export interface ApiState<T> {
  data: T | null;
  error: string | null;
  /** True while the first load is in flight (no data to show yet). */
  loading: boolean;
  /** True while a refresh of existing data is in flight. */
  refreshing: boolean;
  lastUpdated: Date | null;
  refresh: () => Promise<T>;
  setData: Dispatch<SetStateAction<T | null>>;
}

export interface UseApiOptions {
  /** Poll interval in milliseconds. Omit to disable polling. */
  pollMs?: number;
}

/**
 * Fetches data through the supplied fetcher with loading/error/refresh
 * handling and optional polling. The fetcher may change identity between
 * renders; the latest one is always used.
 *
 * `refresh()` returns a Promise that resolves with the fetched data, so
 * callers can await actual data arrival (not just the state update).
 */
export function useApi<T>(
  fetcher: () => Promise<T>,
  deps: ReadonlyArray<unknown>,
  options: UseApiOptions = {},
): ApiState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [tick, setTick] = useState(0);

  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const resolverRef = useRef<((value: T) => void) | null>(null);

  useEffect(() => {
    let cancelled = false;

    (async () => {
      setPending(true);
      try {
        const result = await fetcherRef.current();
        if (cancelled) return;
        setData(result);
        setError(null);
        setLastUpdated(new Date());
        resolverRef.current?.(result);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (!cancelled) setPending(false);
      }
    })();

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  useEffect(() => {
    if (!options.pollMs || options.pollMs <= 0) return;
    const id = setInterval(() => setTick((t) => t + 1), options.pollMs);
    return () => clearInterval(id);
  }, [options.pollMs]);

  const refresh = useCallback((): Promise<T> => {
    return new Promise<T>((resolve) => {
      resolverRef.current = resolve;
      setTick((t) => t + 1);
    });
  }, []);

  return {
    data,
    error,
    loading: pending && data === null && error === null,
    refreshing: pending && data !== null,
    lastUpdated,
    refresh,
    setData,
  };
}
