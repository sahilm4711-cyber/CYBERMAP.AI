/** Shared severity badge + small state components for Phase 5 pages. */

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-300 border-red-500/40",
  HIGH: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  MEDIUM: "bg-yellow-500/15 text-yellow-300 border-yellow-500/40",
  LOW: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  NONE: "bg-zinc-500/15 text-zinc-300 border-zinc-500/40",
};

export function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) {
    return (
      <span className="inline-block rounded border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">
        unavailable
      </span>
    );
  }
  const style =
    SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.NONE;
  return (
    <span
      className={`inline-block rounded border px-2 py-0.5 text-xs font-semibold ${style}`}
    >
      {severity}
    </span>
  );
}

export function KevBadge() {
  return (
    <span className="inline-block rounded border border-red-500/40 bg-red-500/15 px-2 py-0.5 text-xs font-semibold text-red-300">
      KEV
    </span>
  );
}

export function LoadingSkeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div aria-label="Loading" className="animate-pulse space-y-3">
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className="h-10 rounded-lg bg-zinc-800/80" />
      ))}
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}) {
  return (
    <div className="rounded-xl border border-red-900/60 bg-red-950/30 p-5 text-sm">
      <p className="font-semibold text-red-300">Couldn&apos;t load this data</p>
      <p className="mt-1 text-zinc-400">{message}</p>
      <button
        type="button"
        onClick={onRetry}
        className="mt-3 rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-100 hover:bg-zinc-700"
      >
        Retry
      </button>
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-dashed border-zinc-700 bg-zinc-900/30 p-5 text-sm text-zinc-400">
      {message}
    </div>
  );
}

/** Format an ISO date/datetime for display; "unavailable" when absent. */
export function formatDate(value: string | null | undefined): string {
  if (!value) return "unavailable";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}
