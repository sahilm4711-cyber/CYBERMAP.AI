import { z } from "zod";
import { apiGet, apiPost, toQuery } from "@/lib/services/client";

/** Zod schemas mirror backend/app/schemas/intelligence.py + ai.py. */

export const KevListItemSchema = z.object({
  cve_id: z.string(),
  vendor_project: z.string().nullable(),
  product: z.string().nullable(),
  vulnerability_name: z.string().nullable(),
  date_added: z.string().nullable(),
  due_date: z.string().nullable(),
  short_description: z.string().nullable(),
  required_action: z.string().nullable(),
  ransomware_use: z.string().nullable(),
  is_indexed: z.boolean(),
});

export const KevListResponseSchema = z.object({
  items: z.array(KevListItemSchema),
  total: z.number(),
  page: z.number(),
  per_page: z.number(),
  pages: z.number(),
});

export const EpssRankingItemSchema = z.object({
  cve_id: z.string(),
  title: z.string().nullable(),
  severity: z.string().nullable(),
  cvss_score: z.number().nullable(),
  epss_score: z.number(),
  percentile: z.number(),
  model_date: z.string(),
});

export const EpssRankingResponseSchema = z.object({
  items: z.array(EpssRankingItemSchema),
  total: z.number(),
  page: z.number(),
  per_page: z.number(),
  pages: z.number(),
});

export const TimelineEventSchema = z.object({
  type: z.string(),
  date: z.string().nullable(),
  label: z.string(),
  cve_id: z.string().nullable(),
  source: z.string().nullable(),
  status: z.string().nullable(),
});

export const TimelineResponseSchema = z.object({
  events: z.array(TimelineEventSchema),
});

export const MetricExplanationSchema = z.object({
  name: z.string(),
  what_it_measures: z.string(),
  scale: z.string(),
  what_high_means: z.string(),
  what_it_does_not_mean: z.string(),
  limitations: z.array(z.string()),
});

export const MetricsExplainedSchema = z.object({
  note: z.string(),
  metrics: z.array(MetricExplanationSchema),
});

export const AiAnalysisSchema = z.object({
  cve_id: z.string(),
  analysis_type: z.string(),
  ai_mode: z.string(),
  model: z.string().nullable(),
  fallback_reason: z.string().nullable(),
  analysis: z.object({
    executive_summary: z.string(),
    technical_explanation: z.string(),
    root_cause: z.string(),
    potential_impact: z.string(),
    affected_components: z.string(),
    risk_assessment: z.string(),
    defensive_verification: z.string(),
    remediation: z.string(),
    references: z.array(
      z.object({ label: z.string(), url: z.string() }),
    ),
    confidence_and_limitations: z.object({
      confidence: z.string(),
      limitations: z.array(z.string()),
    }),
  }),
  citations: z.array(z.record(z.string(), z.unknown())),
});

export type KevListResponse = z.infer<typeof KevListResponseSchema>;
export type EpssRankingResponse = z.infer<typeof EpssRankingResponseSchema>;
export type TimelineResponse = z.infer<typeof TimelineResponseSchema>;
export type MetricsExplained = z.infer<typeof MetricsExplainedSchema>;
export type AiAnalysis = z.infer<typeof AiAnalysisSchema>;

export async function fetchKev(
  page = 1,
  perPage = 20,
): Promise<KevListResponse> {
  const json = await apiGet<unknown>(
    `/api/v1/intelligence/kev${toQuery({ page, per_page: perPage })}`,
  );
  return KevListResponseSchema.parse(json);
}

export async function fetchEpssRanking(
  page = 1,
  perPage = 20,
): Promise<EpssRankingResponse> {
  const json = await apiGet<unknown>(
    `/api/v1/intelligence/epss-ranking${toQuery({ page, per_page: perPage })}`,
  );
  return EpssRankingResponseSchema.parse(json);
}

export async function fetchTimeline(limit = 50): Promise<TimelineResponse> {
  const json = await apiGet<unknown>(
    `/api/v1/intelligence/timeline${toQuery({ limit })}`,
  );
  return TimelineResponseSchema.parse(json);
}

export async function fetchMetricsExplained(): Promise<MetricsExplained> {
  const json = await apiGet<unknown>("/api/v1/intelligence/metrics-explained");
  return MetricsExplainedSchema.parse(json);
}

/** POST /api/v1/ai/analyze — the Phase 6 AI analyst slot. */
export async function fetchAiAnalysis(cveId: string): Promise<AiAnalysis> {
  const json = await apiPost<unknown>("/api/v1/ai/analyze", {
    cve_id: cveId,
    analysis_type: "simple",
  });
  return AiAnalysisSchema.parse(json);
}
