"use client";

import { useRouter } from "next/navigation";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { DashboardTrends } from "@/lib/services/dashboard";

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#10b981",
  NONE: "#71717a",
  UNKNOWN: "#52525b",
};

const CHART_TEXT = "#a1a1aa";

function ChartCard({
  title,
  hint,
  children,
}: {
  title: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
      <h2 className="text-base font-semibold text-zinc-100">{title}</h2>
      {hint ? <p className="mt-1 text-xs text-zinc-500">{hint}</p> : null}
      <div className="mt-4 h-64">{children}</div>
    </section>
  );
}

export function PublicationTrendChart({
  trends,
}: {
  trends: DashboardTrends;
}) {
  return (
    <ChartCard
      title="CVE publications per day"
      hint="Counts come from the database for the selected date range."
    >
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={trends.publications_per_day}>
          <CartesianGrid stroke="#27272a" strokeDasharray="3 3" />
          <XAxis dataKey="date" tick={{ fill: CHART_TEXT, fontSize: 11 }} />
          <YAxis tick={{ fill: CHART_TEXT, fontSize: 11 }} allowDecimals={false} />
          <Tooltip
            contentStyle={{ background: "#18181b", border: "1px solid #3f3f46" }}
          />
          <Area
            type="monotone"
            dataKey="count"
            stroke="#22d3ee"
            fill="#22d3ee"
            fillOpacity={0.25}
          />
        </AreaChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

export function SeverityDonut({ trends }: { trends: DashboardTrends }) {
  const router = useRouter();
  const data = Object.entries(trends.severity_distribution)
    .filter(([, count]) => count > 0)
    .map(([name, value]) => ({ name, value }));
  return (
    <ChartCard
      title="Severity distribution"
      hint="Click a slice to open the explorer filtered to that severity."
    >
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Tooltip
            contentStyle={{ background: "#18181b", border: "1px solid #3f3f46" }}
          />
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius={55}
            outerRadius={90}
            paddingAngle={2}
            onClick={(_data: unknown, index: number) => {
              const entry = data[index];
              if (entry && entry.name !== "UNKNOWN") {
                router.push(
                  `/vulnerabilities?severity=${encodeURIComponent(entry.name)}`,
                );
              }
            }}
          >
            {data.map((entry) => (
              <Cell
                key={entry.name}
                fill={SEVERITY_COLORS[entry.name] ?? "#71717a"}
              />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

export function CweBarChart({ trends }: { trends: DashboardTrends }) {
  const router = useRouter();
  return (
    <ChartCard
      title="Top CWE weaknesses"
      hint="Click a bar to open the explorer filtered to that CWE."
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={trends.cwe_distribution} layout="vertical">
          <CartesianGrid stroke="#27272a" strokeDasharray="3 3" />
          <XAxis type="number" tick={{ fill: CHART_TEXT, fontSize: 11 }} />
          <YAxis
            type="category"
            dataKey="cwe_id"
            tick={{ fill: CHART_TEXT, fontSize: 11 }}
            width={70}
          />
          <Tooltip
            contentStyle={{ background: "#18181b", border: "1px solid #3f3f46" }}
          />
          <Bar
            dataKey="count"
            fill="#22d3ee"
            onClick={(data: unknown) => {
              const entry = data as { cwe_id?: string } | null;
              if (entry?.cwe_id) {
                router.push(
                  `/vulnerabilities?cwe=${encodeURIComponent(entry.cwe_id)}`,
                );
              }
            }}
          />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

export function KevAdditionsChart({ trends }: { trends: DashboardTrends }) {
  return (
    <ChartCard
      title="KEV additions per day"
      hint="CVEs added to the CISA Known Exploited Vulnerabilities list."
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={trends.kev_additions_per_day}>
          <CartesianGrid stroke="#27272a" strokeDasharray="3 3" />
          <XAxis dataKey="date" tick={{ fill: CHART_TEXT, fontSize: 11 }} />
          <YAxis tick={{ fill: CHART_TEXT, fontSize: 11 }} allowDecimals={false} />
          <Tooltip
            contentStyle={{ background: "#18181b", border: "1px solid #3f3f46" }}
          />
          <Bar dataKey="count" fill="#ef4444" />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

export function EpssDistributionChart({
  trends,
}: {
  trends: DashboardTrends;
}) {
  const data = Object.entries(trends.epss_buckets).map(([bucket, count]) => ({
    bucket,
    count,
  }));
  return (
    <ChartCard
      title="EPSS distribution"
      hint="Each CVE counted once, by its latest EPSS score. EPSS is an exploitation probability, not a severity score."
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data}>
          <CartesianGrid stroke="#27272a" strokeDasharray="3 3" />
          <XAxis dataKey="bucket" tick={{ fill: CHART_TEXT, fontSize: 11 }} />
          <YAxis tick={{ fill: CHART_TEXT, fontSize: 11 }} allowDecimals={false} />
          <Tooltip
            contentStyle={{ background: "#18181b", border: "1px solid #3f3f46" }}
          />
          <Bar dataKey="count" fill="#a78bfa" />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}
