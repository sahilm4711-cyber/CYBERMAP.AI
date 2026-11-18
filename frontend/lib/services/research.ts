import { z } from "zod";
import { apiBaseUrl } from "@/lib/api";

export const CollectionSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  is_public: z.boolean(),
  item_count: z.number(),
  created_at: z.string().nullable(),
  updated_at: z.string().nullable(),
});
export type ResearchCollection = z.infer<typeof CollectionSchema>;

export const CollectionItemSchema = z.object({
  id: z.string(),
  collection_id: z.string(),
  item_type: z.string(),
  item_id: z.string(),
  label: z.string().nullable(),
  name: z.string().nullable(),
  added_at: z.string().nullable(),
});
export type CollectionItem = z.infer<typeof CollectionItemSchema>;

export const NoteSchema = z.object({
  id: z.string(),
  collection_id: z.string().nullable(),
  vulnerability_id: z.string().nullable(),
  title: z.string().nullable(),
  body: z.string(),
  tags: z.array(z.string()).nullable(),
  created_at: z.string().nullable(),
  updated_at: z.string().nullable(),
});
export type ResearchNote = z.infer<typeof NoteSchema>;

export const SavedAnalysisSchema = z.object({
  id: z.string(),
  vulnerability_id: z.string(),
  cve_id: z.string().nullable(),
  analysis_type: z.string(),
  content: z.record(z.string(), z.unknown()),
  ai_mode: z.string(),
  model: z.string().nullable(),
  created_at: z.string().nullable(),
});
export type SavedAnalysis = z.infer<typeof SavedAnalysisSchema>;

export const CompareRowSchema = z.object({
  cve_id: z.string(),
  cvss_score: z.union([z.number(), z.string()]),
  severity: z.string(),
  cwe_ids: z.array(z.string()),
  epss_score: z.union([z.number(), z.string()]),
  epss_percentile: z.union([z.number(), z.string()]),
  kev_listed: z.boolean(),
  published_at: z.string(),
});
export type CompareRow = z.infer<typeof CompareRowSchema>;

export const CollectionStatusSchema = z.object({
  collection_id: z.string(),
  status: z.string(),
  note_id: z.string().nullable(),
  note_title: z.string().nullable(),
});
export type CollectionStatus = z.infer<typeof CollectionStatusSchema>;

function paginated<T extends z.ZodTypeAny>(item: T) {
  return z.object({
    items: z.array(item),
    total: z.number(),
    skip: z.number(),
    limit: z.number(),
  });
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

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
      detail = body.detail ?? JSON.stringify(body);
    } catch {
      /* keep default detail */
    }
    throw new ApiError(res.status, `${res.status}: ${detail}`);
  }
  if (res.status === 204) return undefined as T;
  return schema.parse(await res.json());
}

async function requestNoBody(path: string, init?: RequestInit): Promise<void> {
  const res = await fetch(`${apiBaseUrl()}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    throw new ApiError(res.status, `${res.status}: ${res.statusText}`);
  }
}

const BASE = "/api/v1/research";

export async function listCollections() {
  return request(`${BASE}/collections`, paginated(CollectionSchema));
}

export async function createCollection(input: {
  name: string;
  description?: string;
  is_public?: boolean;
}) {
  return request(`${BASE}/collections`, CollectionSchema, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export async function updateCollection(
  id: string,
  input: { name?: string; description?: string; is_public?: boolean },
) {
  return request(`${BASE}/collections/${id}`, CollectionSchema, {
    method: "PATCH",
    body: JSON.stringify(input),
  });
}

export async function deleteCollection(id: string) {
  return requestNoBody(`${BASE}/collections/${id}`, { method: "DELETE" });
}

export async function getCollectionStatus(id: string) {
  return request(
    `${BASE}/collections/${id}/status`,
    CollectionStatusSchema,
  );
}

export async function listCollectionItems(id: string) {
  return request(
    `${BASE}/collections/${id}/items`,
    paginated(CollectionItemSchema),
  );
}

export async function addCollectionItem(
  id: string,
  input: { item_type: string; item_id: string },
) {
  return request(`${BASE}/collections/${id}/items`, CollectionItemSchema, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export async function removeCollectionItem(
  id: string,
  itemId: string,
  itemType: string,
) {
  return requestNoBody(
    `${BASE}/collections/${id}/items/${itemId}?item_type=${encodeURIComponent(itemType)}`,
    { method: "DELETE" },
  );
}

export function exportUrl(id: string, format: "json" | "csv") {
  return `${apiBaseUrl()}${BASE}/collections/${id}/export?format=${format}`;
}

export async function listBookmarks() {
  return request(`${BASE}/bookmarks`, paginated(CollectionItemSchema));
}

export async function addBookmark(input: {
  item_type: string;
  item_id: string;
}) {
  return request(`${BASE}/bookmarks`, CollectionItemSchema, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export async function removeBookmark(itemType: string, itemId: string) {
  return requestNoBody(
    `${BASE}/bookmarks/${encodeURIComponent(itemType)}/${itemId}`,
    { method: "DELETE" },
  );
}

export async function listNotes(filter?: {
  collection_id?: string;
  vulnerability_id?: string;
  tag?: string;
}) {
  const params = new URLSearchParams();
  if (filter?.collection_id) params.set("collection_id", filter.collection_id);
  if (filter?.vulnerability_id)
    params.set("vulnerability_id", filter.vulnerability_id);
  if (filter?.tag) params.set("tag", filter.tag);
  const qs = params.toString();
  return request(
    `${BASE}/notes${qs ? `?${qs}` : ""}`,
    paginated(NoteSchema),
  );
}

export async function createNote(input: {
  title?: string;
  body: string;
  tags?: string[];
  collection_id?: string;
  vulnerability_id?: string;
}) {
  return request(`${BASE}/notes`, NoteSchema, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export async function updateNote(
  id: string,
  input: { title?: string; body?: string; tags?: string[] },
) {
  return request(`${BASE}/notes/${id}`, NoteSchema, {
    method: "PATCH",
    body: JSON.stringify(input),
  });
}

export async function deleteNote(id: string) {
  return requestNoBody(`${BASE}/notes/${id}`, { method: "DELETE" });
}

export async function listAnalyses() {
  return request(`${BASE}/analyses`, paginated(SavedAnalysisSchema));
}

export async function deleteAnalysis(id: string) {
  return requestNoBody(`${BASE}/analyses/${id}`, { method: "DELETE" });
}

export async function compareCves(cveIds: string[]) {
  const schema = z.object({ comparisons: z.array(CompareRowSchema) });
  return request(`${BASE}/compare`, schema, {
    method: "POST",
    body: JSON.stringify({ cve_ids: cveIds }),
  });
}
