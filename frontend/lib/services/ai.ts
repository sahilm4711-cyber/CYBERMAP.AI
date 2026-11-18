import { z } from "zod";
import { apiBaseUrl } from "@/lib/api";
import { ApiError } from "@/lib/services/client";

export const CitationSchema = z.object({
  cve_id: z.string().optional(),
  cwe_id: z.string().optional(),
  technique_id: z.string().optional(),
  source: z.string().optional(),
  url: z.string().nullable().optional(),
});
export type Citation = z.infer<typeof CitationSchema>;

export const ChatMessageSchema = z.object({
  id: z.string(),
  role: z.string(),
  content: z.string(),
  citations: z.array(CitationSchema).nullable(),
  created_at: z.string(),
});
export type ChatMessage = z.infer<typeof ChatMessageSchema>;

export const ConversationSummarySchema = z.object({
  id: z.string(),
  title: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
  message_count: z.number(),
});
export type ConversationSummary = z.infer<
  typeof ConversationSummarySchema
>;

export const ConversationDetailSchema = z.object({
  id: z.string(),
  title: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
  messages: z.array(ChatMessageSchema),
});
export type ConversationDetail = z.infer<
  typeof ConversationDetailSchema
>;

export const ChatResponseSchema = z.object({
  answer: z.string(),
  citations: z.array(CitationSchema),
  conversation_id: z.string(),
  ai_mode: z.string(),
  model: z.string().nullable(),
});
export type ChatResponse = z.infer<typeof ChatResponseSchema>;

export const AiStatusSchema = z.object({
  provider_configured: z.boolean(),
  provider: z.string().nullable(),
  mode: z.string(),
});
export type AiStatus = z.infer<typeof AiStatusSchema>;

const BASE = "/api/v1/ai";

async function request<T>(
  path: string,
  schema: z.ZodType<T>,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(`${apiBaseUrl()}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      /* keep default detail */
    }
    throw new ApiError(res.status, `${res.status}: ${detail}`);
  }
  if (res.status === 204) return undefined as T;
  return schema.parse(await res.json());
}

export async function getAiStatus(): Promise<AiStatus> {
  return request(`${BASE}/status`, AiStatusSchema);
}

export async function listConversations(): Promise<
  ConversationSummary[]
> {
  return request(
    `${BASE}/conversations`,
    z.array(ConversationSummarySchema),
  );
}

export async function getConversation(
  id: string,
): Promise<ConversationDetail> {
  return request(
    `${BASE}/conversations/${encodeURIComponent(id)}`,
    ConversationDetailSchema,
  );
}

export async function deleteConversation(id: string): Promise<void> {
  await request(
    `${BASE}/conversations/${encodeURIComponent(id)}`,
    z.undefined(),
    { method: "DELETE" },
  );
}

export async function sendChat(input: {
  question: string;
  conversation_id?: string | null;
}): Promise<ChatResponse> {
  return request(`${BASE}/chat`, ChatResponseSchema, {
    method: "POST",
    body: JSON.stringify(input),
  });
}
