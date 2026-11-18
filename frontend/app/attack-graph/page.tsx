"use client";

import { useState } from "react";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import {
  edgeColour,
  NODE_COLOURS,
  useAttackGraph,
} from "@/hooks/useAttackGraph";
import type { GraphNodeType } from "@/lib/services/graph";

const TYPE_LABELS: Record<GraphNodeType, string> = {
  vulnerability: "CVE",
  cwe: "CWE",
  attack_technique: "Technique",
  product: "Product",
  vendor: "Vendor",
};

const TYPE_ORDER: GraphNodeType[] = [
  "vulnerability",
  "cwe",
  "attack_technique",
  "product",
  "vendor",
];

/** Human-readable rendering of a node-detail field value. */
function renderFieldValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string" || typeof value === "number") {
    return String(value);
  }
  if (Array.isArray(value)) {
    return value
      .map((item) =>
        typeof item === "object" && item !== null
          ? JSON.stringify(item)
          : String(item),
      )
      .join("; ");
  }
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/**
 * Attack knowledge graph (Phase 7). Centred on one CVE: its CWEs,
 * the techniques linked to those CWEs (stored links only), affected
 * products and vendors. Click a node for details and to expand it.
 */
export default function AttackGraphPage() {
  const graph = useAttackGraph();
  const [seedInput, setSeedInput] = useState("");
  const [depth, setDepth] = useState<1 | 2>(1);
  const [searchInput, setSearchInput] = useState("");

  const empty =
    graph.status === "ready" && graph.nodes.length === 0;

  return (
    <div className="flex flex-col gap-4">
      <section>
        <h1 className="text-2xl font-bold tracking-tight">
          Attack Knowledge Graph
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-zinc-400">
          One CVE, its weaknesses, the ATT&amp;CK techniques linked to
          those weaknesses, and the products and vendors it affects.
          Edges carry their source — solid edges are verified records,
          dashed edges are inferred.
        </p>
      </section>

      {/* Controls: seed CVE, depth, search */}
      <section className="flex flex-wrap items-end gap-3 rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
        <label className="flex flex-col gap-1 text-xs text-zinc-400">
          Seed CVE
          <input
            value={seedInput}
            onChange={(e) => setSeedInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && seedInput.trim()) {
                void graph.loadGraph(seedInput.trim(), depth);
              }
            }}
            placeholder={graph.seed ?? "CVE-2024-12345"}
            className="w-48 rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-zinc-400">
          Depth
          <select
            value={depth}
            onChange={(e) =>
              setDepth(e.target.value === "2" ? 2 : 1)
            }
            className="rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
          >
            <option value={1}>1 — direct neighbours</option>
            <option value={2}>2 — one more hop</option>
          </select>
        </label>
        <button
          type="button"
          disabled={!seedInput.trim() || graph.status === "loading"}
          onClick={() => void graph.loadGraph(seedInput.trim(), depth)}
          className="rounded-md bg-cyan-500 px-4 py-2 text-sm font-semibold text-zinc-950 disabled:opacity-40"
        >
          Load graph
        </button>

        <label className="relative flex flex-col gap-1 text-xs text-zinc-400">
          Search entities
          <input
            value={searchInput}
            onChange={(e) => {
              setSearchInput(e.target.value);
              void graph.runSearch(e.target.value);
            }}
            placeholder="CVE, CWE, technique, product…"
            className="w-64 rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
          />
          {graph.searchResults.length > 0 && (
            <ul className="absolute top-full z-20 mt-1 w-64 overflow-hidden rounded-md border border-zinc-700 bg-zinc-950 shadow-lg">
              {graph.searchResults.map((result) => (
                <li key={result.id}>
                  <button
                    type="button"
                    onClick={() => {
                      setSearchInput(result.label);
                      void graph.selectSearchResult(result);
                    }}
                    className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-zinc-100 hover:bg-zinc-800"
                  >
                    <span
                      className="inline-block h-2.5 w-2.5 shrink-0 rounded-full"
                      style={{
                        backgroundColor: NODE_COLOURS[result.type],
                      }}
                    />
                    <span className="truncate">
                      {result.label}
                      {result.subtitle
                        ? ` — ${result.subtitle}`
                        : ""}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </label>
        {graph.searching && (
          <span className="pb-2 text-xs text-zinc-500">Searching…</span>
        )}
      </section>

      {/* Entity-type filters */}
      <section
        aria-label="Entity type filters"
        className="flex flex-wrap gap-2"
      >
        {TYPE_ORDER.map((type) => (
          <button
            key={type}
            type="button"
            onClick={() => graph.toggleType(type)}
            aria-pressed={graph.visibleTypes[type]}
            className={`flex items-center gap-2 rounded-full border px-3 py-1 text-xs ${
              graph.visibleTypes[type]
                ? "border-zinc-600 bg-zinc-800 text-zinc-100"
                : "border-zinc-800 bg-transparent text-zinc-500 line-through"
            }`}
          >
            <span
              className="inline-block h-2.5 w-2.5 rounded-full"
              style={{ backgroundColor: NODE_COLOURS[type] }}
            />
            {TYPE_LABELS[type]}
          </button>
        ))}
      </section>

      {graph.status === "loading" && (
        <p className="text-sm text-zinc-400">Loading graph…</p>
      )}
      {graph.status === "error" && (
        <div className="rounded-xl border border-red-900 bg-red-950/40 p-4 text-sm text-red-200">
          {graph.error ??
            "Could not load the graph. Is the backend running and are you signed in?"}
        </div>
      )}
      {empty && (
        <div className="rounded-xl border border-dashed border-zinc-700 bg-zinc-900/30 p-5 text-sm text-zinc-400">
          No graph data — ingest data first. Index a CVE (Phase 4
          ingestion), then enter its ID above or use search.
        </div>
      )}

      {graph.note && (
        <p className="rounded-xl border border-amber-900 bg-amber-950/40 p-3 text-sm text-amber-200">
          {graph.note}
        </p>
      )}
      {graph.hasMore && (
        <p className="text-sm text-zinc-400">
          Showing {graph.nodes.length} of {graph.totalNodes} nodes.
          Narrow the seed or expand one node at a time for the rest.
        </p>
      )}

      <div className="flex flex-col gap-4 lg:flex-row">
        <div className="h-[560px] flex-1 rounded-xl border border-zinc-800 bg-zinc-950">
          <ReactFlow
            nodes={graph.nodes}
            edges={graph.edges}
            onNodesChange={graph.onNodesChange}
            onEdgesChange={graph.onEdgesChange}
            onNodeClick={(_event, node) => {
              void graph.selectNode(node.id);
            }}
            fitView
          >
            <Background />
            <Controls />
            <MiniMap
              nodeColor={(node) => {
                const type = node.id.split(
                  ":",
                )[0] as GraphNodeType;
                return NODE_COLOURS[type] ?? "#71717a";
              }}
            />
          </ReactFlow>
        </div>

        {/* Details panel */}
        <aside className="w-full shrink-0 rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 lg:w-80">
          <h2 className="text-base font-semibold">Details</h2>
          {graph.selectedLoading && (
            <p className="mt-2 text-sm text-zinc-400">
              Loading details…
            </p>
          )}
          {!graph.selectedLoading && !graph.selected && (
            <p className="mt-2 text-sm text-zinc-400">
              Click a node in the graph to see its full record, its
              neighbours, and its mitigations (for techniques).
            </p>
          )}
          {graph.selected && (
            <div className="mt-3 flex flex-col gap-3">
              <div>
                <span
                  className="inline-block rounded-full px-2 py-0.5 text-xs font-semibold"
                  style={{
                    backgroundColor: `${NODE_COLOURS[graph.selected.type]}33`,
                    color: NODE_COLOURS[graph.selected.type],
                  }}
                >
                  {TYPE_LABELS[graph.selected.type]}
                </span>
                <p className="mt-2 text-base font-semibold">
                  {graph.selected.label}
                </p>
                {graph.selected.subtitle && (
                  <p className="text-sm text-zinc-400">
                    {graph.selected.subtitle}
                  </p>
                )}
              </div>
              <dl className="space-y-2 text-sm">
                {Object.entries(graph.selected.fields).map(
                  ([key, value]) =>
                    value !== null &&
                    value !== undefined &&
                    value !== "" && (
                      <div key={key}>
                        <dt className="text-xs uppercase tracking-wide text-zinc-500">
                          {key.replace(/_/g, " ")}
                        </dt>
                        <dd className="break-words text-zinc-200">
                          {renderFieldValue(value)}
                        </dd>
                      </div>
                    ),
                )}
              </dl>
              {graph.selected.type === "vulnerability" &&
                graph.selected.detail_url && (
                  <a
                    href={graph.selected.detail_url}
                    className="text-sm text-cyan-400 underline"
                  >
                    Open CVE detail page
                  </a>
                )}
              <p className="text-sm text-zinc-400">
                {graph.selected.neighbours.length} direct neighbour
                {graph.selected.neighbours.length === 1 ? "" : "s"}
              </p>
              <button
                type="button"
                onClick={() => void graph.expandSelected()}
                className="rounded-md bg-zinc-800 px-4 py-2 text-sm font-semibold text-zinc-100 hover:bg-zinc-700"
              >
                Expand this node
              </button>
            </div>
          )}
        </aside>
      </div>

      {/* Legend */}
      <section className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 text-sm text-zinc-400">
        <h2 className="text-base font-semibold text-zinc-100">Legend</h2>
        <div className="mt-2 flex flex-wrap gap-x-6 gap-y-2">
          {TYPE_ORDER.map((type) => (
            <span key={type} className="flex items-center gap-2">
              <span
                className="inline-block h-3 w-3 rounded-full"
                style={{ backgroundColor: NODE_COLOURS[type] }}
              />
              {TYPE_LABELS[type]}
            </span>
          ))}
        </div>
        <div className="mt-3 flex flex-wrap gap-x-6 gap-y-2">
          {["HAS_WEAKNESS", "EXPLOITS", "AFFECTS", "PROVIDES"].map(
            (rel) => (
              <span key={rel} className="flex items-center gap-2">
                <span
                  className="inline-block h-0.5 w-8"
                  style={{ backgroundColor: edgeColour(rel) }}
                />
                {rel}
              </span>
            ),
          )}
          <span className="flex items-center gap-2">
            <span
              className="inline-block h-0 w-8 border-t-2 border-dashed border-zinc-400"
            />
            Inferred edge (dashed)
          </span>
          <span className="flex items-center gap-2">
            <span className="inline-block h-0.5 w-8 bg-zinc-400" />
            Verified edge (solid)
          </span>
        </div>
        <p className="mt-3 text-xs text-zinc-500">
          Verified edges come from stored records (NVD, MITRE). Inferred
          edges are computed, not stored — they are dashed and labelled
          with their reason. Technique links only appear where a stored
          relationship row links a CWE to a technique; a technique whose
          text merely mentions a CWE is never linked.
        </p>
      </section>
    </div>
  );
}
