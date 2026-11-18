import { z } from "zod";
import { apiBaseUrl } from "@/lib/api";
import { ApiError } from "@/lib/services/research";

export const TopicSummarySchema = z.object({
  slug: z.string(),
  title: z.string(),
});
export type TopicSummary = z.infer<typeof TopicSummarySchema>;

export const KnowledgeQuestionSchema = z.object({
  question: z.string(),
  options: z.array(z.string()).length(4),
  answer_index: z.number().int().min(0).max(3),
  explanation: z.string(),
});
export type KnowledgeQuestion = z.infer<typeof KnowledgeQuestionSchema>;

export const DefensiveExampleSchema = z.object({
  title: z.string(),
  language: z.string(),
  code: z.string(),
  explanation: z.string(),
});
export type DefensiveExample = z.infer<typeof DefensiveExampleSchema>;

export const RelatedRecordSchema = z.object({
  cve_id: z.string(),
  severity: z.string().nullable(),
  cvss_score: z.number().nullable(),
  description: z.string(),
  related_cwe_id: z.string().nullable(),
});
export type RelatedRecord = z.infer<typeof RelatedRecordSchema>;

export const TopicDetailSchema = z.object({
  slug: z.string(),
  title: z.string(),
  levels: z.object({
    beginner: z.string(),
    intermediate: z.string(),
    advanced: z.string(),
  }),
  key_points: z.array(z.string()),
  defensive_examples: z.array(DefensiveExampleSchema),
  related_cwe_ids: z.array(z.string()),
  knowledge_check: z.array(KnowledgeQuestionSchema),
  related_real_records: z.array(RelatedRecordSchema),
});
export type TopicDetail = z.infer<typeof TopicDetailSchema>;

export async function listTopics(): Promise<TopicSummary[]> {
  const res = await fetch(`${apiBaseUrl()}/api/v1/learning/topics`, {
    credentials: "include",
    cache: "no-store",
  });
  if (!res.ok) {
    throw new ApiError(res.status, `${res.status}: ${res.statusText}`);
  }
  const body = z.object({ topics: z.array(TopicSummarySchema) }).parse(
    await res.json(),
  );
  return body.topics;
}

export async function getTopic(slug: string): Promise<TopicDetail> {
  const res = await fetch(
    `${apiBaseUrl()}/api/v1/learning/topics/${encodeURIComponent(slug)}`,
    { credentials: "include", cache: "no-store" },
  );
  if (!res.ok) {
    throw new ApiError(res.status, `${res.status}: ${res.statusText}`);
  }
  return TopicDetailSchema.parse(await res.json());
}
