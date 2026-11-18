import { Suspense } from "react";
import HealthSection from "@/components/HealthSection";

/**
 * Home page (Phase 2). Shows the backend health status and an honest
 * empty state: no vulnerability data has been ingested yet, so no
 * statistics are displayed. Real dashboard content arrives in Phase 5.
 */
export default async function Home() {
  return (
    <div className="flex flex-col gap-8">
      <section>
        <h1 className="text-3xl font-bold tracking-tight">
          Understand Vulnerabilities. Connect Threats.
        </h1>
        <p className="mt-2 max-w-2xl text-zinc-400">
          CyberMap AI collects public vulnerability intelligence from NVD,
          CISA KEV, FIRST EPSS, MITRE ATT&amp;CK and CWE, and helps
          researchers understand it with AI-powered analysis. This build is
          the Phase 2 foundation — the platform shell, the API, and the
          connection between them.
        </p>
      </section>

      <Suspense
        fallback={
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5 text-sm text-zinc-400">
            Checking backend status…
          </div>
        }
      >
        <HealthSection />
      </Suspense>

      <section
        aria-label="Data status"
        className="rounded-xl border border-dashed border-zinc-700 bg-zinc-900/30 p-5"
      >
        <h2 className="text-base font-semibold text-zinc-100">
          No intelligence data yet
        </h2>
        <p className="mt-2 text-sm leading-6 text-zinc-400">
          The dashboard, vulnerability explorer, knowledge graph and AI
          assistant need indexed data. Data ingestion runs in Phase 4
          (NVD, CISA KEV, EPSS, MITRE ATT&amp;CK, CWE). Until then, this
          page shows no CVE counts, charts or rankings — a platform must
          never display fabricated live statistics.
        </p>
        <p className="mt-3 text-sm text-zinc-500">
          What works now: backend health endpoints, API docs at{" "}
          <a
            className="text-cyan-400 underline"
            href="http://localhost:8000/docs"
          >
            localhost:8000/docs
          </a>
          , and this live status check above.
        </p>
      </section>

      <section aria-label="Roadmap" className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
        <h2 className="text-base font-semibold text-zinc-100">Build progress</h2>
        <ol className="mt-3 list-decimal space-y-1 pl-5 text-sm text-zinc-400">
          <li>
            <span className="text-emerald-400">Done</span> — Phase 1:
            architecture, database design, roadmap
          </li>
          <li>
            <span className="text-emerald-400">Done</span> — Phase 2:
            monorepo foundation, health endpoints, Docker Compose
          </li>
          <li>Phase 3 — Database models, migrations, authentication</li>
          <li>Phase 4 — Intelligence ingestion (NVD, KEV, EPSS, MITRE)</li>
          <li>Phase 5 — Dashboard, explorer, threat intelligence center</li>
          <li>Phase 6 — AI analyst and research assistant (with non-AI fallback)</li>
          <li>Phase 7 — Attack knowledge graph</li>
          <li>Phase 8 — Research workspace and learning center</li>
          <li>Phase 9 — Security review and quality assurance</li>
          <li>Phase 10 — Final delivery and documentation</li>
        </ol>
      </section>
    </div>
  );
}
