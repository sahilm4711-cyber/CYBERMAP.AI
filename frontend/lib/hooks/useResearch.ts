import { useCallback, useEffect, useState } from "react";
import {
  ApiError,
  listAnalyses,
  listBookmarks,
  listCollections,
  listNotes,
  type ResearchCollection,
  type ResearchNote,
  type SavedAnalysis,
  type CollectionItem,
} from "@/lib/services/research";

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refresh: () => void;
}

/**
 * Fetch-on-mount/refetch hook. Loading is derived, not set inside
 * the effect: initial load shows as loading while data is null,
 * and `refresh` (an event handler) marks the refetch as pending.
 * State is only updated from the promise callbacks.
 */
function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const refresh = useCallback(() => {
    setRefreshing(true);
    setTick((t) => t + 1);
  }, []);

  useEffect(() => {
    let cancelled = false;
    fn()
      .then((result) => {
        if (!cancelled) {
          setData(result);
          setError(null);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(
            err instanceof ApiError
              ? err.status === 401
                ? "You are not logged in. Log in to use the research workspace."
                : err.message
              : "Could not reach the backend.",
          );
        }
      })
      .finally(() => {
        if (!cancelled) setRefreshing(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick, ...deps]);

  const loading = refreshing || (data === null && error === null);
  return { data, loading, error, refresh };
}

export function useCollections() {
  const state = useAsync(async () => (await listCollections()).items, []);
  return {
    ...state,
    collections: state.data as ResearchCollection[] | null,
  };
}

export function useBookmarks() {
  const state = useAsync(async () => (await listBookmarks()).items, []);
  return { ...state, bookmarks: state.data as CollectionItem[] | null };
}

export function useNotes(tag?: string) {
  const state = useAsync(
    async () => (await listNotes(tag ? { tag } : undefined)).items,
    [tag],
  );
  return { ...state, notes: state.data as ResearchNote[] | null };
}

export function useSavedAnalyses() {
  const state = useAsync(async () => (await listAnalyses()).items, []);
  return { ...state, analyses: state.data as SavedAnalysis[] | null };
}
