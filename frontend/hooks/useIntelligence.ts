import { useMutation, useQuery } from "@tanstack/react-query";
import {
  fetchAiAnalysis,
  fetchEpssRanking,
  fetchKev,
  fetchMetricsExplained,
  fetchTimeline,
} from "@/lib/services/intelligence";

export function useKev(page: number, perPage = 20) {
  return useQuery({
    queryKey: ["intelligence", "kev", page, perPage],
    queryFn: () => fetchKev(page, perPage),
  });
}

export function useEpssRanking(page: number, perPage = 20) {
  return useQuery({
    queryKey: ["intelligence", "epss-ranking", page, perPage],
    queryFn: () => fetchEpssRanking(page, perPage),
  });
}

export function useTimeline() {
  return useQuery({
    queryKey: ["intelligence", "timeline"],
    queryFn: () => fetchTimeline(50),
  });
}

export function useMetricsExplained() {
  return useQuery({
    queryKey: ["intelligence", "metrics-explained"],
    queryFn: fetchMetricsExplained,
  });
}

/** AI analysis slot (Phase 6 endpoint): run on demand per CVE. */
export function useAiAnalysis() {
  return useMutation({
    mutationFn: (cveId: string) => fetchAiAnalysis(cveId),
  });
}
