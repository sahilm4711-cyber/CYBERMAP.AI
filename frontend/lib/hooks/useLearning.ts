import { useCallback, useEffect, useState } from "react";
import {
  getTopic,
  listTopics,
  type TopicDetail,
  type TopicSummary,
} from "@/lib/services/learning";
import { ApiError } from "@/lib/services/research";

export function useTopics() {
  const [topics, setTopics] = useState<TopicSummary[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    listTopics()
      .then((result) => {
        if (!cancelled) setTopics(result);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(
            err instanceof ApiError && err.status === 401
              ? "You are not logged in. Log in to use the learning center."
              : "Could not reach the backend.",
          );
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return { topics, loading, error };
}

export function useTopic(slug: string | null) {
  const [topic, setTopic] = useState<TopicDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const refresh = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    if (!slug) {
      return;
    }
    let cancelled = false;
    getTopic(slug)
      .then((result) => {
        if (!cancelled) {
          setTopic(result);
          setError(null);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(
            err instanceof ApiError
              ? err.message
              : "Could not load this topic.",
          );
        }
      });
    return () => {
      cancelled = true;
    };
  }, [slug, tick]);

  // Loading is derived: a topic is being fetched whenever the
  // selected slug has no matching loaded topic and no error yet.
  const loading =
    slug !== null && (topic === null || topic.slug !== slug) && error === null;

  return { topic, loading, error, refresh };
}
