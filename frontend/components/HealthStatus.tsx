"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchHealth, type Health } from "@/lib/api";

/**
 * Live backend status card. Uses TanStack Query so the status refreshes
 * automatically; the server-rendered page passes the first result in.
 */
export default function HealthStatus({ initial }: { initial: Health | null }) {
  const { data } = useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
    initialData: initial ?? undefined,
    refetchInterval: 30_000,
  });

  const health = data ?? initial;
  const up = health?.status === "ok";

  return (
    <section
      aria-label="Backend status"
      className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5"
    >
      <div className="flex items-center gap-3">
        <span
          aria-hidden
          className={`inline-block h-3 w-3 rounded-full ${
            up ? "bg-emerald-400" : "bg-red-500"
          }`}
        />
        <h2 className="text-base font-semibold text-zinc-100">
          {up ? "Backend online" : "Backend unreachable"}
        </h2>
      </div>
      {health ? (
        <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-4">
          <div>
            <dt className="text-zinc-500">Service</dt>
            <dd className="font-mono text-zinc-200">{health.service}</dd>
          </div>
          <div>
            <dt className="text-zinc-500">Version</dt>
            <dd className="font-mono text-zinc-200">{health.version}</dd>
          </div>
          <div>
            <dt className="text-zinc-500">Environment</dt>
            <dd className="font-mono text-zinc-200">{health.environment}</dd>
          </div>
          <div>
            <dt className="text-zinc-500">AI mode</dt>
            <dd className="font-mono text-zinc-200">
              {health.ai_mode === "fallback"
                ? "Non-AI fallback"
                : `Provider (${health.ai_mode})`}
            </dd>
          </div>
          <div>
            <dt className="text-zinc-500">Database</dt>
            <dd className="font-mono text-zinc-200">{health.database}</dd>
          </div>
          <div className="col-span-2 sm:col-span-3">
            <dt className="text-zinc-500">Last check</dt>
            <dd className="font-mono text-zinc-200">
              {new Date(health.timestamp).toLocaleString()}
            </dd>
          </div>
        </dl>
      ) : (
        <p className="mt-3 text-sm text-zinc-400">
          Start the backend first:{" "}
          <code className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-xs text-cyan-300">
            cd backend && uvicorn app.main:app --reload --port 8000
          </code>
        </p>
      )}
    </section>
  );
}
