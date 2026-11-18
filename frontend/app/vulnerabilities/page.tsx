"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useState } from "react";
import {
  EmptyState,
  ErrorState,
  formatDate,
  KevBadge,
  LoadingSkeleton,
  SeverityBadge,
} from "@/components/Phase5Shared";
import { useVulnerabilities } from "@/hooks/useVulnerabilities";
import type { VulnerabilitySort } from "@/lib/services/vulnerabilities";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];

function Explorer() {
  const searchParams = useSearchParams();
  const [q, setQ] = useState("");
  const [debouncedQ, setDebouncedQ] = useState("");
  const [severity, setSeverity] = useState<string[]>(
    searchParams.getAll("severity"),
  );
  const [cwe, setCwe] = useState(searchParams.get("cwe") ?? "");
  const [minCvss, setMinCvss] = useState("");
  const [maxCvss, setMaxCvss] = useState("");
  const [minEpss, setMinEpss] = useState("");
  const [maxEpss, setMaxEpss] = useState("");
  const [vendor, setVendor] = useState("");
  const [product, setProduct] = useState("");
  const [kevOnly, setKevOnly] = useState(
    searchParams.get("kev_only") === "true",
  );
  const [publishedFrom, setPublishedFrom] = useState("");
  const [publishedTo, setPublishedTo] = useState("");
  const [sort, setSort] = useState<VulnerabilitySort>("newest");
  const [page, setPage] = useState(1);

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQ(q), 400);
    return () => clearTimeout(timer);
  }, [q]);

  const filters = useMemo(
    () => ({
      q: debouncedQ || undefined,
      severity: severity.length ? severity : undefined,
      cwe: cwe || undefined,
      min_cvss: minCvss ? Number(minCvss) : undefined,
      max_cvss: maxCvss ? Number(maxCvss) : undefined,
      min_epss: minEpss ? Number(minEpss) : undefined,
      max_epss: maxEpss ? Number(maxEpss) : undefined,
      vendor: vendor || undefined,
      product: product || undefined,
      kev_only: kevOnly || undefined,
      published_from: publishedFrom || undefined,
      published_to: publishedTo || undefined,
      sort,
      page,
      per_page: 20,
    }),
    [
      debouncedQ,
      severity,
      cwe,
      minCvss,
      maxCvss,
      minEpss,
      maxEpss,
      vendor,
      product,
      kevOnly,
      publishedFrom,
      publishedTo,
      sort,
      page,
    ],
  );

  const query = useVulnerabilities(filters);

  function toggleSeverity(value: string) {
    setPage(1);
    setSeverity((prev) =>
      prev.includes(value)
        ? prev.filter((s) => s !== value)
        : [...prev, value],
    );
  }

  function resetFilters() {
    setQ("");
    setSeverity([]);
    setCwe("");
    setMinCvss("");
    setMaxCvss("");
    setMinEpss("");
    setMaxEpss("");
    setVendor("");
    setProduct("");
    setKevOnly(false);
    setPublishedFrom("");
    setPublishedTo("");
    setSort("newest");
    setPage(1);
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold">Vulnerabilities</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Search and filter every indexed CVE. All rows come from the live
          database.
        </p>
      </div>

      <div className="flex flex-col gap-3 rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
        <input
          type="search"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setPage(1);
          }}
          placeholder="Search by CVE ID or text (e.g. CVE-2024-0001, widget)…"
          className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500"
        />
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs uppercase tracking-wide text-zinc-500">
            Severity
          </span>
          {SEVERITIES.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => toggleSeverity(s)}
              className={`rounded-lg border px-2.5 py-1 text-xs ${
                severity.includes(s)
                  ? "border-cyan-400 bg-cyan-400/10 text-cyan-300"
                  : "border-zinc-700 bg-zinc-800 text-zinc-300"
              }`}
            >
              {s}
            </button>
          ))}
          <label className="ml-2 flex items-center gap-1.5 text-sm text-zinc-300">
            <input
              type="checkbox"
              checked={kevOnly}
              onChange={(e) => {
                setKevOnly(e.target.checked);
                setPage(1);
              }}
            />
            KEV only
          </label>
          <select
            value={sort}
            onChange={(e) => {
              setSort(e.target.value as VulnerabilitySort);
              setPage(1);
            }}
            className="ml-auto rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-100"
            aria-label="Sort results"
          >
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first</option>
            <option value="severity">Severity</option>
            <option value="cvss">CVSS (highest)</option>
            <option value="epss">EPSS (highest)</option>
            <option value="risk">Risk (EPSS, then CVSS)</option>
          </select>
        </div>
        <div className="grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
          <label className="flex flex-col gap-1 text-zinc-400">
            CWE
            <input
              value={cwe}
              onChange={(e) => {
                setCwe(e.target.value);
                setPage(1);
              }}
              placeholder="CWE-79"
              className="rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-zinc-100"
            />
          </label>
          <label className="flex flex-col gap-1 text-zinc-400">
            CVSS range
            <span className="flex gap-1">
              <input
                type="number"
                min={0}
                max={10}
                step={0.1}
                value={minCvss}
                onChange={(e) => {
                  setMinCvss(e.target.value);
                  setPage(1);
                }}
                placeholder="min"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-zinc-100"
              />
              <input
                type="number"
                min={0}
                max={10}
                step={0.1}
                value={maxCvss}
                onChange={(e) => {
                  setMaxCvss(e.target.value);
                  setPage(1);
                }}
                placeholder="max"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-zinc-100"
              />
            </span>
          </label>
          <label className="flex flex-col gap-1 text-zinc-400">
            EPSS range
            <span className="flex gap-1">
              <input
                type="number"
                min={0}
                max={1}
                step={0.05}
                value={minEpss}
                onChange={(e) => {
                  setMinEpss(e.target.value);
                  setPage(1);
                }}
                placeholder="min"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-zinc-100"
              />
              <input
                type="number"
                min={0}
                max={1}
                step={0.05}
                value={maxEpss}
                onChange={(e) => {
                  setMaxEpss(e.target.value);
                  setPage(1);
                }}
                placeholder="max"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-zinc-100"
              />
            </span>
          </label>
          <label className="flex flex-col gap-1 text-zinc-400">
            Vendor / product
            <span className="flex gap-1">
              <input
                value={vendor}
                onChange={(e) => {
                  setVendor(e.target.value);
                  setPage(1);
                }}
                placeholder="vendor"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-zinc-100"
              />
              <input
                value={product}
                onChange={(e) => {
                  setProduct(e.target.value);
                  setPage(1);
                }}
                placeholder="product"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-zinc-100"
              />
            </span>
          </label>
          <label className="flex flex-col gap-1 text-zinc-400">
            Published from
            <input
              type="date"
              value={publishedFrom}
              onChange={(e) => {
                setPublishedFrom(e.target.value);
                setPage(1);
              }}
              className="rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-zinc-100"
            />
          </label>
          <label className="flex flex-col gap-1 text-zinc-400">
            Published to
            <input
              type="date"
              value={publishedTo}
              onChange={(e) => {
                setPublishedTo(e.target.value);
                setPage(1);
              }}
              className="rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-zinc-100"
            />
          </label>
        </div>
        <div>
          <button
            type="button"
            onClick={resetFilters}
            className="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-700"
          >
            Reset filters
          </button>
        </div>
      </div>

      {query.isPending ? (
        <LoadingSkeleton lines={5} />
      ) : query.isError || !query.data ? (
        <ErrorState
          message="The vulnerability list could not be loaded. Check that the API is running and you are logged in."
          onRetry={() => void query.refetch()}
        />
      ) : query.data.total === 0 ? (
        <EmptyState message="No vulnerabilities match these filters. Try widening the search or resetting the filters." />
      ) : (
        <>
          <p className="text-sm text-zinc-400">
            {query.data.total} result{query.data.total === 1 ? "" : "s"} ·
            page {query.data.page} of {query.data.pages}
          </p>
          <div className="overflow-x-auto rounded-xl border border-zinc-800">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="bg-zinc-900 text-xs uppercase text-zinc-500">
                  <th className="px-3 py-2">CVE</th>
                  <th className="px-3 py-2">Severity</th>
                  <th className="px-3 py-2">CVSS</th>
                  <th className="px-3 py-2">EPSS</th>
                  <th className="px-3 py-2">KEV</th>
                  <th className="px-3 py-2">CWE</th>
                  <th className="px-3 py-2">Published</th>
                </tr>
              </thead>
              <tbody>
                {query.data.items.map((item) => (
                  <tr
                    key={item.cve_id}
                    className="border-t border-zinc-800 hover:bg-zinc-900/60"
                  >
                    <td className="px-3 py-2">
                      <Link
                        href={`/vulnerability/${item.cve_id}`}
                        className="font-mono text-cyan-400 hover:underline"
                      >
                        {item.cve_id}
                      </Link>
                    </td>
                    <td className="px-3 py-2">
                      <SeverityBadge severity={item.severity} />
                    </td>
                    <td className="px-3 py-2">
                      {item.cvss_score ?? "unavailable"}
                    </td>
                    <td className="px-3 py-2">
                      {item.epss_score != null
                        ? item.epss_score.toFixed(3)
                        : "unavailable"}
                    </td>
                    <td className="px-3 py-2">
                      {item.is_kev ? <KevBadge /> : "—"}
                    </td>
                    <td className="px-3 py-2">
                      {item.cwe_ids.length ? item.cwe_ids.join(", ") : "—"}
                    </td>
                    <td className="px-3 py-2">
                      {formatDate(item.published_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm disabled:opacity-40"
            >
              Previous
            </button>
            <span className="text-sm text-zinc-400">
              Page {query.data.page} of {query.data.pages}
            </span>
            <button
              type="button"
              disabled={page >= query.data.pages}
              onClick={() => setPage((p) => p + 1)}
              className="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </>
      )}
    </div>
  );
}

export default function VulnerabilitiesPage() {
  return (
    <Suspense fallback={<LoadingSkeleton lines={5} />}>
      <Explorer />
    </Suspense>
  );
}
