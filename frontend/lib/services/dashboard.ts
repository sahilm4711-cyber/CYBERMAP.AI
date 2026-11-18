import { z } from "zod";
import { apiGet, toQuery } from "@/lib/services/client";

/** Zod schemas mirror backend/app/schemas/dashboard.py. */

export const SourceSyncStatusSchema = z.object({
  name: z.string(),
  display_name: z.string().nullable(),
  last_sync_at: z.string().nullable(),
  last_sync_status: z.string().nullable(),
  is_enabled: z.boolean(),
});

export const RecentCveSchema = z.object({
  cve_id: z.string(),
  title: z.string().nullable(),
  severity: z.string().nullable(),
  cvss_score: z.number().nullable(),
  published_at: z.string().nullable(),
});

export const DashboardSummarySchema = z.object({
  total_cves: z.number(),
  critical: z.number(),
  high: z.number(),
  medium: z.number(),
  low: z.number(),
  none_severity: z.number(),
  unknown_severity: z.number(),
  kev_count: z.number(),
  high_epss_count: z.number(),
  recently_published: z.array(RecentCveSchema),
  last_sync_at: z.string().nullable(),
  sources: z.array(SourceSyncStatusSchema),
  range_from: z.string().nullable().optional(),
  range_to: z.string().nullable().optional(),
});

export const DailyCountSchema = z.object({
  date: z.string(),
  count: z.number(),
});

export const DashboardTrendsSchema = z.object({
  range_from: z.string(),
  range_to: z.string(),
  publications_per_day: z.array(DailyCountSchema),
  severity_distribution: z.record(z.string(), z.number()),
  cwe_distribution: z.array(
    z.object({
      cwe_id: z.string(),
      name: z.string().nullable(),
      count: z.number(),
    }),
  ),
  kev_additions_per_day: z.array(DailyCountSchema),
  epss_buckets: z.record(z.string(), z.number()),
});

export type DashboardSummary = z.infer<typeof DashboardSummarySchema>;
export type DashboardTrends = z.infer<typeof DashboardTrendsSchema>;
export type SourceSyncStatus = z.infer<typeof SourceSyncStatusSchema>;

export interface DateRange {
  from?: string;
  to?: string;
}

export async function fetchDashboardSummary(
  range: DateRange = {},
): Promise<DashboardSummary> {
  const json = await apiGet<unknown>(
    `/api/v1/dashboard/summary${toQuery(range)}`,
  );
  return DashboardSummarySchema.parse(json);
}

export async function fetchDashboardTrends(
  range: DateRange = {},
): Promise<DashboardTrends> {
  const json = await apiGet<unknown>(
    `/api/v1/dashboard/trends${toQuery(range)}`,
  );
  return DashboardTrendsSchema.parse(json);
}
