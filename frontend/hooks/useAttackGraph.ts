import { useCallback, useEffect, useRef, useState } from "react";
import {
  type Edge,
  type Node,
  useEdgesState,
  useNodesState,
} from "@xyflow/react";

import {
  expandNode,
  fetchGraph,
  fetchNodeDetail,
  GraphApiError,
  searchGraph,
  type GraphEdgeData,
  type GraphNodeData,
  type GraphNodeType,
  type NodeDetailData,
  type SearchResultData,
} from "@/lib/services/graph";

/** Node colours per entity type (shared with the page legend). */
export const NODE_COLOURS: Record<GraphNodeType, string> = {
  vulnerability: "#22d3ee",
  cwe: "#f59e0b",
  attack_technique: "#ef4444",
  product: "#22c55e",
  vendor: "#9ca3af",
};

/** Edge stroke colour by relationship name. */
export function edgeColour(relationship: string): string {
  switch (relationship) {
    case "HAS_WEAKNESS":
      return "#f59e0b";
    case "EXPLOITS":
      return "#ef4444";
    case "AFFECTS":
      return "#22c55e";
    case "PROVIDES":
      return "#9ca3af";
    default:
      return "#71717a";
  }
}

function toFlowNode(node: GraphNodeData, position: {
  x: number;
  y: number;
}): Node {
  const colour = NODE_COLOURS[node.type];
  return {
    id: node.id,
    position,
    data: {
      label: node.subtitle
        ? `${node.label}\n${node.subtitle}`
        : node.label,
      // Entity type, so the page can filter without reading a ref
      // during render.
      entityType: node.type,
    },
    style: {
      background: "#18181b",
      border: `2px solid ${colour}`,
      borderRadius: 8,
      color: "#f4f4f5",
      fontSize: 12,
      padding: 8,
      whiteSpace: "pre-line",
      width: 200,
    },
  };
}

function toFlowEdge(edge: GraphEdgeData): Edge {
  const inferred = edge.confidence === "inferred";
  return {
    id: edge.id,
    source: edge.from,
    target: edge.to,
    label: edge.relationship,
    style: {
      stroke: edgeColour(edge.relationship),
      strokeWidth: 1.5,
      ...(inferred ? { strokeDasharray: "6 4" } : {}),
    },
    labelStyle: { fill: "#d4d4d8", fontSize: 10 },
  };
}

/** Layered layout: BFS depth from the seed, stacked vertically. */
function layoutNodes(
  nodes: GraphNodeData[],
  edges: GraphEdgeData[],
  seedId: string | null,
): Map<string, { x: number; y: number }> {
  const adjacency = new Map<string, string[]>();
  for (const edge of edges) {
    for (const [a, b] of [
      [edge.from, edge.to],
      [edge.to, edge.from],
    ]) {
      const list = adjacency.get(a) ?? [];
      list.push(b);
      adjacency.set(a, list);
    }
  }
  const depth = new Map<string, number>();
  const queue: string[] = [];
  if (seedId && nodes.some((n) => n.id === seedId)) {
    depth.set(seedId, 0);
    queue.push(seedId);
  }
  while (queue.length > 0) {
    const current = queue.shift()!;
    const d = depth.get(current)!;
    for (const next of adjacency.get(current) ?? []) {
      if (!depth.has(next)) {
        depth.set(next, d + 1);
        queue.push(next);
      }
    }
  }
  const maxDepth = Math.max(0, ...depth.values());
  for (const node of nodes) {
    if (!depth.has(node.id)) depth.set(node.id, maxDepth + 1);
  }
  const byDepth = new Map<number, GraphNodeData[]>();
  for (const node of nodes) {
    const d = depth.get(node.id)!;
    const list = byDepth.get(d) ?? [];
    list.push(node);
    byDepth.set(d, list);
  }
  const positions = new Map<string, { x: number; y: number }>();
  for (const [d, group] of byDepth) {
    group.forEach((node, i) => {
      positions.set(node.id, { x: d * 280, y: i * 110 });
    });
  }
  return positions;
}

export type GraphStatus = "idle" | "loading" | "ready" | "error";

export function useAttackGraph() {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [status, setStatus] = useState<GraphStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [totalNodes, setTotalNodes] = useState(0);
  const [seed, setSeed] = useState<string | null>(null);
  const [selected, setSelected] = useState<NodeDetailData | null>(null);
  const [selectedLoading, setSelectedLoading] = useState(false);
  const [visibleTypes, setVisibleTypes] = useState<
    Record<GraphNodeType, boolean>
  >({
    vulnerability: true,
    cwe: true,
    attack_technique: true,
    product: true,
    vendor: true,
  });
  const [searchResults, setSearchResults] = useState<SearchResultData[]>(
    [],
  );
  const [searching, setSearching] = useState(false);

  // Raw graph data (unfiltered) so toggles never lose nodes.
  const rawNodes = useRef<Map<string, GraphNodeData>>(new Map());
  const rawEdges = useRef<Map<string, GraphEdgeData>>(new Map());
  const seedRef = useRef<string | null>(null);

  const applyGraph = useCallback(
    (
      newNodes: GraphNodeData[],
      newEdges: GraphEdgeData[],
      seedId: string | null,
    ) => {
      for (const node of newNodes) rawNodes.current.set(node.id, node);
      for (const edge of newEdges) {
        rawEdges.current.set(
          `${edge.from}|${edge.to}|${edge.relationship}`,
          edge,
        );
      }
      const allNodes = [...rawNodes.current.values()];
      const allEdges = [...rawEdges.current.values()];
      const positions = layoutNodes(allNodes, allEdges, seedId);
      setNodes(
        allNodes.map((n) =>
          toFlowNode(n, positions.get(n.id) ?? { x: 0, y: 0 }),
        ),
      );
      setEdges(allEdges.map(toFlowEdge));
    },
    [setEdges, setNodes],
  );

  const loadGraph = useCallback(
    async (seedCve: string, depth: 1 | 2 = 1) => {
      setStatus("loading");
      setError(null);
      setSelected(null);
      rawNodes.current.clear();
      rawEdges.current.clear();
      try {
        const data = await fetchGraph(seedCve, depth);
        const seedId =
          data.nodes.find((n) => n.label === data.seed)?.id ?? null;
        seedRef.current = seedId;
        setSeed(data.seed);
        setNote(data.note);
        setHasMore(data.has_more);
        setTotalNodes(data.total_nodes);
        if (data.nodes.length === 0) {
          setStatus("ready");
          setNodes([]);
          setEdges([]);
          return;
        }
        applyGraph(data.nodes, data.edges, seedId);
        setStatus("ready");
      } catch (err) {
        setStatus("error");
        setError(
          err instanceof GraphApiError
            ? err.message
            : "Could not load the graph.",
        );
      }
    },
    [applyGraph, setEdges, setNodes],
  );

  // Auto-load the first indexed CVE on mount (via search), so the
  // page is not an empty canvas when data exists.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const result = await searchGraph("CVE-", 5);
        const first = result.results.find(
          (r) => r.type === "vulnerability",
        );
        if (!cancelled && first) {
          await loadGraph(first.label, 1);
        } else if (!cancelled) {
          setStatus("ready");
        }
      } catch {
        if (!cancelled) {
          setStatus("ready");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [loadGraph]);

  const selectNode = useCallback(
    async (nodeId: string) => {
      setSelectedLoading(true);
      try {
        const detail = await fetchNodeDetail(nodeId);
        setSelected(detail);
      } catch {
        setSelected(null);
      } finally {
        setSelectedLoading(false);
      }
    },
    [],
  );

  const expandSelected = useCallback(async () => {
    if (!selected) return;
    try {
      const data = await expandNode(selected.type, selected.id);
      applyGraph(data.nodes, data.edges, seedRef.current);
      // Refresh the detail panel so its neighbour list is current.
      const detail = await fetchNodeDetail(selected.id);
      setSelected(detail);
    } catch {
      setError("Could not expand that node.");
    }
  }, [applyGraph, selected]);

  const runSearch = useCallback(async (q: string) => {
    const query = q.trim();
    if (query.length < 2) {
      setSearchResults([]);
      return;
    }
    setSearching(true);
    try {
      const result = await searchGraph(query);
      setSearchResults(result.results);
    } catch {
      setSearchResults([]);
    } finally {
      setSearching(false);
    }
  }, []);

  const selectSearchResult = useCallback(
    async (result: SearchResultData) => {
      setSearchResults([]);
      if (result.type === "vulnerability") {
        await loadGraph(result.label, 1);
        return;
      }
      // Non-CVE result: show the node plus its neighbours.
      try {
        const detail = await fetchNodeDetail(result.id);
        setSelected(detail);
        applyGraph(
          [detail, ...detail.neighbours].map((n) => ({
            id: n.id,
            type: n.type,
            label: n.label,
            subtitle: n.subtitle,
            detail_url: n.detail_url,
          })),
          detail.neighbour_edges,
          result.id,
        );
        setStatus("ready");
      } catch {
        setError("Could not load that entity.");
      }
    },
    [applyGraph, loadGraph],
  );

  const toggleType = useCallback((type: GraphNodeType) => {
    setVisibleTypes((prev) => ({ ...prev, [type]: !prev[type] }));
  }, []);

  const visibleNodes = nodes.filter((node) => {
    const entityType = (node.data as { entityType?: GraphNodeType })
      .entityType;
    return entityType ? visibleTypes[entityType] : true;
  });
  const visibleNodeIds = new Set(visibleNodes.map((n) => n.id));
  const visibleEdges = edges.filter(
    (edge) => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target),
  );

  return {
    nodes: visibleNodes,
    edges: visibleEdges,
    onNodesChange,
    onEdgesChange,
    status,
    error,
    note,
    hasMore,
    totalNodes,
    seed,
    selected,
    selectedLoading,
    visibleTypes,
    searchResults,
    searching,
    loadGraph,
    selectNode,
    expandSelected,
    runSearch,
    selectSearchResult,
    toggleType,
    setSelected,
  };
}
