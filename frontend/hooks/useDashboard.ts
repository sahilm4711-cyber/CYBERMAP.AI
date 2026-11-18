import { useQuery } from "@tanstack/react-query";
import {
  fetchDashboardSummary,
  fetchDashboardTrends,
  type DateRange,
} from "@/lib/services/dashboard";

export function useDashboardSummary(range: DateRange) {
  return useQuery({
    queryKey: ["dashboard", "summary", range.from ?? null, range.to ?? null],
    queryFn: () => fetchDashboardSummary(range),
  });
}

export function useDashboardTrends(range: DateRange) {
  return useQuery({
    queryKey: ["dashboard", "trends", range.from ?? null, range.to ?? null],
    queryFn: () => fetchDashboardTrends(range),
  });
}
