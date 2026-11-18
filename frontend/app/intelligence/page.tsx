"use client";

import Link from "next/link";
import { useState } from "react";
import {
  EmptyState,
  ErrorState,
  formatDate,
  LoadingSkeleton,
  SeverityBadge,
} from "@/components/Phase5Shared";
import {
  useEpssRanking,
  useKev,
  useMetricsExplained,
  useTimeline,
} from "@/hooks/useIntelligence";

function Pagination({
  page,
  pages,
  onPage,
}: {
  page: number;
  pages: number;
  onPage: (page: number) => void;
}) {
  return (
    <div className="mt-4 flex items-center gap-3">
      <button
        type="button"
        disabled={page <= 1}
        onClick={() => onPage(page - 1)}
        className="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm disabled:opacity-40"
      >
        Previous
      </button>
      <span className="text-sm text-zinc-400">
        Page {page} of {pages}
      </span>
      <button
        type="button"
        disabled={page >= pages}
        onClick={() => onPage(page + 1)}
        className="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm disabled:opacity-40"
      >
        Next
      </button>
    </div>
  );
}

export default function IntelligencePage() {
  const [kevPage, setKevPage] = useState(1);
  const [epssPage, setEpssPage] = useState(1);
  const kev = useKev(kevPage);
  const epss = useEpssRanking(epssPage);
  const timeline = useTimeline();
  const metrics = useMetricsExplained();

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold">Threat Intelligence Center</h1>
        <p className="mt-1 text-sm text-zinc-400">
          What is confirmed exploited, what is likely to be exploited, and
          what just happened — all from the live database.
        </p>
      </div>

      <section className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
        <h2 className="text-base font-semibold">
          CISA KEV — newly added vulnerabilities
        </h2>
        {kev.isPending ? (
          <div className="mt-3">
            <LoadingSkeleton lines={4} />
          </div>
        ) : kev.isError || !kev.data ? (
          <div className="mt-3">
            <ErrorState
              message="The KEV list could not be loaded."
              onRetry={() => void kev.refetch()}
            />
          </div>
        ) : kev.data.total === 0 ? (
          <div className="mt-3">
            <EmptyState message="No KEV entries indexed yet." />
          </div>
        ) : (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="text-xs uppercase text-zinc-500">
                  <th className="py-2 pr-2">CVE</th>
                  <th className="py-2 pr-2">Vendor / product</th>
                  <th className="py-2 pr-2">Added</th>
                  <th className="py-2 pr-2">Due date</th>
                  <th className="py-2">Ransomware</th>
                </tr>
              </thead>
              <tbody>
                {kev.data.items.map((item) => (
                  <tr key={item.cve_id} className="border-t border-zinc-800">
                    <td className="py-2 pr-2">
                      {item.is_indexed ? (
                        <Link
                          href={`/vulnerability/${item.cve_id}`}
                          className="font-mono text-cyan-400 hover:underline"
                        >
                          {item.cve_id}
                        </Link>
                      ) : (
                        <span className="font-mono text-zinc-300">
                          {item.cve_id}
                        </span>
                      )}
                    </td>
                    <td className="py-2 pr-2">
                      {item.vendor_project ?? "—"} / {item.product ?? "—"}
                    </td>
                    <td className="py-2 pr-2">{formatDate(item.date_added)}</td>
                    <td className="py-2 pr-2">{formatDate(item.due_date)}</td>
                    <td className="py-2">{item.ransomware_use ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination
              page={kev.data.page}
              pages={kev.data.pages}
              onPage={setKevPage}
            />
          </div>
        )}
      </section>

      <section className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
        <h2 className="text-base font-semibold">
          EPSS ranking — most likely to be exploited
        </h2>
        {epss.isPending ? (
          <div className="mt-3">
            <LoadingSkeleton lines={4} />
          </div>
        ) : epss.isError || !epss.data ? (
          <div className="mt-3">
            <ErrorState
              message="The EPSS ranking could not be loaded."
              onRetry={() => void epss.refetch()}
            />
          </div>
        ) : epss.data.total === 0 ? (
          <div className="mt-3">
            <EmptyState message="No EPSS scores indexed yet." />
          </div>
        ) : (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="text-xs uppercase text-zinc-500">
                  <th className="py-2 pr-2">CVE</th>
                  <th className="py-2 pr-2">Severity</th>
                  <th className="py-2 pr-2">CVSS</th>
                  <th className="py-2 pr-2">EPSS</th>
                  <th className="py-2">Percentile</th>
                </tr>
              </thead>
              <tbody>
                {epss.data.items.map((item) => (
                  <tr key={item.cve_id} className="border-t border-zinc-800">
                    <td className="py-2 pr-2">
                      <Link
                        href={`/vulnerability/${item.cve_id}`}
                        className="font-mono text-cyan-400 hover:underline"
                      >
                        {item.cve_id}
                      </Link>
                    </td>
                    <td className="py-2 pr-2">
                      <SeverityBadge severity={item.severity} />
                    </td>
                    <td className="py-2 pr-2">
                      {item.cvss_score ?? "unavailable"}
                    </td>
                    <td className="py-2 pr-2 font-semibold">
                      {item.epss_score.toFixed(3)}
                    </td>
                    <td className="py-2">
                      {(item.percentile * 100).toFixed(1)}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination
              page={epss.data.page}
              pages={epss.data.pages}
              onPage={setEpssPage}
            />
          </div>
        )}
      </section>

      <section className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
        <h2 className="text-base font-semibold">Timeline — recent events</h2>
        {timeline.isPending ? (
          <div className="mt-3">
            <LoadingSkeleton lines={4} />
          </div>
        ) : timeline.isError || !timeline.data ? (
          <div className="mt-3">
            <ErrorState
              message="The timeline could not be loaded."
              onRetry={() => void timeline.refetch()}
            />
          </div>
        ) : timeline.data.events.length === 0 ? (
          <div className="mt-3">
            <EmptyState message="No events yet — no CVEs, KEV additions or ingestion runs recorded." />
          </div>
        ) : (
          <ol className="mt-3 space-y-2 text-sm">
            {timeline.data.events.map((event, i) => (
              <li key={i} className="flex items-start gap-3">
                <span
                  className={`mt-0.5 rounded border px-2 py-0.5 text-xs font-semibold ${
                    event.type === "kev"
                      ? "border-red-500/40 bg-red-500/15 text-red-300"
                      : event.type === "cve"
                        ? "border-cyan-500/40 bg-cyan-500/10 text-cyan-300"
                        : "border-zinc-700 bg-zinc-800 text-zinc-300"
                  }`}
                >
                  {event.type.toUpperCase()}
                </span>
                <span className="text-zinc-300">{event.label}</span>
                <span className="ml-auto shrink-0 text-xs text-zinc-500">
                  {formatDate(event.date)}
                </span>
              </li>
            ))}
          </ol>
        )}
      </section>

      <section className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
        <h2 className="text-base font-semibold">
          CVSS vs EPSS vs KEV — what each one actually means
        </h2>
        {metrics.isPending ? (
          <div className="mt-3">
            <LoadingSkeleton lines={3} />
          </div>
        ) : metrics.isError || !metrics.data ? (
          <div className="mt-3">
            <ErrorState
              message="The explainer could not be loaded."
              onRetry={() => void metrics.refetch()}
            />
          </div>
        ) : (
          <>
            <p className="mt-2 rounded-lg border border-yellow-500/40 bg-yellow-500/10 p-3 text-sm text-yellow-200">
              {metrics.data.note}
            </p>
            <div className="mt-4 grid gap-4 lg:grid-cols-3">
              {metrics.data.metrics.map((m) => (
                <article
                  key={m.name}
                  className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 text-sm"
                >
                  <h3 className="font-semibold text-zinc-100">{m.name}</h3>
                  <p className="mt-2 leading-6 text-zinc-300">
                    {m.what_it_measures}
                  </p>
                  <p className="mt-2 text-xs text-zinc-500">
                    Scale: {m.scale}
                  </p>
                  <p className="mt-2 leading-6 text-zinc-300">
                    <span className="font-semibold text-zinc-100">
                      High means:{" "}
                    </span>
                    {m.what_high_means}
                  </p>
                  <p className="mt-2 leading-6 text-zinc-300">
                    <span className="font-semibold text-zinc-100">
                      It does not mean:{" "}
                    </span>
                    {m.what_it_does_not_mean}
                  </p>
                  <h4 className="mt-3 font-semibold text-zinc-100">
                    Limitations
                  </h4>
                  <ul className="mt-1 list-disc space-y-1 pl-5 text-zinc-400">
                    {m.limitations.map((limitation) => (
                      <li key={limitation}>{limitation}</li>
                    ))}
                  </ul>
                </article>
              ))}
            </div>
          </>
        )}
      </section>
    </div>
  );
}
