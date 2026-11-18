"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import {
  CweBarChart,
  EpssDistributionChart,
  KevAdditionsChart,
  PublicationTrendChart,
  SeverityDonut,
} from "@/components/DashboardCharts";
import {
  EmptyState,
  ErrorState,
  formatDate,
  LoadingSkeleton,
  SeverityBadge,
} from "@/components/Phase5Shared";
import { useDashboardSummary, useDashboardTrends } from "@/hooks/useDashboard";
import type { DateRange } from "@/lib/services/dashboard";

type Preset = "7" | "30" | "90" | "custom";

function isoDaysAgo(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() - days);
  return d.toISOString().slice(0, 10);
}

function todayIso(): string {
  return new Date().toISOString().slice(0, 10);
}

function rangeForPreset(preset: Preset, custom: DateRange): DateRange {
  if (preset === "custom") return custom;
  const days = Number(preset);
  return { from: isoDaysAgo(days - 1), to: todayIso() };
}

function StatCard({
  label,
  value,
  sub,
}: {
  label: string;
  value: number | string;
  sub?: string;
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
      <p className="text-xs uppercase tracking-wide text-zinc-500">{label}</p>
      <p className="mt-1 text-2xl font-bold text-zinc-100">{value}</p>
      {sub ? <p className="mt-1 text-xs text-zinc-500">{sub}</p> : null}
    </div>
  );
}

export default function DashboardPage() {
  const [preset, setPreset] = useState<Preset>("30");
  // Dates are computed after mount (useEffect), not during render:
  // Next.js prerendering rejects `new Date()` evaluated at render time.
  const [custom, setCustom] = useState<DateRange>({});
  const [ready, setReady] = useState(false);

  useEffect(() => {
    // Intentional: dates must be read after mount, not during
    // prerender (Next.js rejects `new Date()` at render time).
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setCustom({ from: isoDaysAgo(29), to: todayIso() });
    setReady(true);
  }, []);

  const range = useMemo(
    () => (ready ? rangeForPreset(preset, custom) : {}),
    [ready, preset, custom],
  );

  const summary = useDashboardSummary(range);
  const trends = useDashboardTrends(range);

  if (!ready || summary.isPending || trends.isPending) {
    return (
      <div className="flex flex-col gap-6">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <LoadingSkeleton lines={6} />
      </div>
    );
  }

  if (summary.isError || trends.isError || !summary.data || !trends.data) {
    return (
      <div className="flex flex-col gap-6">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <ErrorState
          message="The backend could not be reached, or returned data that failed validation. Check that the API is running and you are logged in."
          onRetry={() => {
            void summary.refetch();
            void trends.refetch();
          }}
        />
      </div>
    );
  }

  const data = summary.data;
  const trendData = trends.data;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Live counts from the indexed vulnerability database — nothing here
            is fabricated.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {(["7", "30", "90"] as Preset[]).map((p) => (
            <button
              key={p}
              type="button"
              onClick={() => setPreset(p)}
              className={`rounded-lg border px-3 py-1.5 text-sm ${
                preset === p
                  ? "border-cyan-400 bg-cyan-400/10 text-cyan-300"
                  : "border-zinc-700 bg-zinc-800 text-zinc-300"
              }`}
            >
              {p} days
            </button>
          ))}
          <button
            type="button"
            onClick={() => setPreset("custom")}
            className={`rounded-lg border px-3 py-1.5 text-sm ${
              preset === "custom"
                ? "border-cyan-400 bg-cyan-400/10 text-cyan-300"
                : "border-zinc-700 bg-zinc-800 text-zinc-300"
            }`}
          >
            Custom
          </button>
          {preset === "custom" && (
            <span className="flex items-center gap-2 text-sm text-zinc-400">
              <input
                type="date"
                value={custom.from ?? ""}
                onChange={(e) =>
                  setCustom((c) => ({ ...c, from: e.target.value }))
                }
                className="rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-zinc-100"
              />
              to
              <input
                type="date"
                value={custom.to ?? ""}
                onChange={(e) =>
                  setCustom((c) => ({ ...c, to: e.target.value }))
                }
                className="rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-zinc-100"
              />
            </span>
          )}
        </div>
      </div>

      {data.total_cves === 0 ? (
        <EmptyState message="No vulnerabilities indexed yet. Run an ingestion sync to populate the dashboard — no statistics are shown until real data exists." />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
            <StatCard label="Total CVEs" value={data.total_cves} />
            <StatCard label="Critical" value={data.critical} />
            <StatCard label="High" value={data.high} />
            <StatCard
              label="In CISA KEV"
              value={data.kev_count}
              sub="Confirmed exploited"
            />
            <StatCard
              label="High EPSS (≥ 0.7)"
              value={data.high_epss_count}
              sub="Likely to be exploited"
            />
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <PublicationTrendChart trends={trendData} />
            <SeverityDonut trends={trendData} />
            <CweBarChart trends={trendData} />
            <KevAdditionsChart trends={trendData} />
            <EpssDistributionChart trends={trendData} />
            <section className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
              <h2 className="text-base font-semibold text-zinc-100">
                Sync status
              </h2>
              <p className="mt-1 text-xs text-zinc-500">
                Last sync across all sources:{" "}
                {data.last_sync_at
                  ? new Date(data.last_sync_at).toLocaleString()
                  : "never — no sync has run yet"}
              </p>
              <ul className="mt-4 space-y-2 text-sm">
                {data.sources.map((s) => (
                  <li
                    key={s.name}
                    className="flex items-center justify-between gap-2"
                  >
                    <span className="text-zinc-200">
                      {s.display_name ?? s.name}
                    </span>
                    <span className="text-zinc-400">
                      {s.last_sync_status ?? "never"}
                      {s.last_sync_at
                        ? ` · ${formatDate(s.last_sync_at)}`
                        : ""}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          </div>

          <section className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
            <h2 className="text-base font-semibold text-zinc-100">
              Recently published
            </h2>
            {data.recently_published.length === 0 ? (
              <p className="mt-2 text-sm text-zinc-400">
                No CVEs were published in the selected range.
              </p>
            ) : (
              <table className="mt-3 w-full text-left text-sm">
                <thead>
                  <tr className="text-xs uppercase text-zinc-500">
                    <th className="py-2 pr-2">CVE</th>
                    <th className="py-2 pr-2">Severity</th>
                    <th className="py-2 pr-2">CVSS</th>
                    <th className="py-2">Published</th>
                  </tr>
                </thead>
                <tbody>
                  {data.recently_published.map((cve) => (
                    <tr key={cve.cve_id} className="border-t border-zinc-800">
                      <td className="py-2 pr-2">
                        <Link
                          href={`/vulnerability/${cve.cve_id}`}
                          className="font-mono text-cyan-400 hover:underline"
                        >
                          {cve.cve_id}
                        </Link>
                      </td>
                      <td className="py-2 pr-2">
                        <SeverityBadge severity={cve.severity} />
                      </td>
                      <td className="py-2 pr-2">
                        {cve.cvss_score ?? "unavailable"}
                      </td>
                      <td className="py-2">{formatDate(cve.published_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </>
      )}
    </div>
  );
}
