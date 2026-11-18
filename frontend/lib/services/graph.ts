import { z } from "zod";

import { apiBaseUrl } from "@/lib/api";

/** Zod schemas for GET /api/v1/graph responses (see backend/app/schemas/graph.py). */

export const GraphNodeTypeSchema = z.enum([
  "vulnerability",
  "cwe",
  "attack_technique",
  "product",
  "vendor",
]);

export type GraphNodeType = z.infer<typeof GraphNodeTypeSchema>;

export const GraphNodeSchema = z.object({
  id: z.string(),
  type: GraphNodeTypeSchema,
  label: z.string(),
  subtitle: z.string().nullable(),
  detail_url: z.string().nullable(),
});

export type GraphNodeData = z.infer<typeof GraphNodeSchema>;

export const GraphEdgeSchema = z.object({
  id: z.string(),
  from: z.string(),
  to: z.string(),
  relationship: z.string(),
  source: z.string(),
  confidence: z.string(),
});

export type GraphEdgeData = z.infer<typeof GraphEdgeSchema>;

export const GraphResponseSchema = z.object({
  seed: z.string().nullable(),
  nodes: z.array(GraphNodeSchema),
  edges: z.array(GraphEdgeSchema),
  has_more: z.boolean(),
  total_nodes: z.number(),
  total_edges: z.number(),
  note: z.string().nullable(),
});

export type GraphResponseData = z.infer<typeof GraphResponseSchema>;

export const NodeDetailSchema = z.object({
  id: z.string(),
  type: GraphNodeTypeSchema,
  label: z.string(),
  subtitle: z.string().nullable(),
  detail_url: z.string().nullable(),
  fields: z.record(z.string(), z.unknown()),
  neighbours: z.array(GraphNodeSchema),
  neighbour_edges: z.array(GraphEdgeSchema),
});

export type NodeDetailData = z.infer<typeof NodeDetailSchema>;

export const SearchResultSchema = z.object({
  id: z.string(),
  type: GraphNodeTypeSchema,
  label: z.string(),
  subtitle: z.string().nullable(),
});

export const SearchResponseSchema = z.object({
  query: z.string(),
  results: z.array(SearchResultSchema),
});

export type SearchResultData = z.infer<typeof SearchResultSchema>;

export const ExpandResponseSchema = z.object({
  node_id: z.string(),
  node_type: GraphNodeTypeSchema,
  nodes: z.array(GraphNodeSchema),
  edges: z.array(GraphEdgeSchema),
  has_more: z.boolean(),
  total_nodes: z.number(),
  total_edges: z.number(),
});

export type ExpandResponseData = z.infer<typeof ExpandResponseSchema>;

export const CweTechniquesSchema = z.object({
  cwe_id: z.string(),
  techniques: z.array(
    z.object({
      id: z.string(),
      technique_id: z.string(),
      name: z.string(),
      tactic: z.string().nullable(),
      relationship: z.string(),
      source: z.string(),
      confidence: z.string(),
    }),
  ),
});

export type CweTechniquesData = z.infer<typeof CweTechniquesSchema>;

export class GraphApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "GraphApiError";
    this.status = status;
  }
}

async function graphFetch<T>(
  path: string,
  schema: z.ZodType<T>,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(`${apiBaseUrl()}${path}`, {
    credentials: "include",
    cache: "no-store",
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (res.status === 401) {
    throw new GraphApiError(401, "Not signed in — please log in first.");
  }
  if (res.status === 404) {
    throw new GraphApiError(404, "Not found in the indexed data.");
  }
  if (!res.ok) {
    throw new GraphApiError(
      res.status,
      `Graph request failed (${res.status}).`,
    );
  }
  return schema.parse(await res.json());
}

export function fetchGraph(
  seedCve: string,
  depth: 1 | 2 = 1,
  limit = 50,
): Promise<GraphResponseData> {
  const params = new URLSearchParams({
    seed_cve: seedCve,
    depth: String(depth),
    limit: String(limit),
  });
  return graphFetch(`/api/v1/graph?${params}`, GraphResponseSchema);
}

export function searchGraph(
  q: string,
  limit = 20,
): Promise<z.infer<typeof SearchResponseSchema>> {
  const params = new URLSearchParams({ q, limit: String(limit) });
  return graphFetch(
    `/api/v1/graph/search?${params}`,
    SearchResponseSchema,
  );
}

/** ``nodeId`` is a prefixed id such as ``cwe:<uuid>``. */
export function fetchNodeDetail(nodeId: string): Promise<NodeDetailData> {
  const [type, ...rest] = nodeId.split(":");
  const key = rest.join(":");
  return graphFetch(
    `/api/v1/graph/node/${type}/${encodeURIComponent(key)}`,
    NodeDetailSchema,
  );
}

export function expandNode(
  nodeType: GraphNodeType,
  nodeId: string,
): Promise<ExpandResponseData> {
  return graphFetch("/api/v1/graph/expand", ExpandResponseSchema, {
    method: "POST",
    body: JSON.stringify({ node_type: nodeType, node_id: nodeId }),
  });
}

export function fetchCweTechniques(
  cweId: string,
): Promise<CweTechniquesData> {
  return graphFetch(
    `/api/v1/graph/cwe/${encodeURIComponent(cweId)}/techniques`,
    CweTechniquesSchema,
  );
}
