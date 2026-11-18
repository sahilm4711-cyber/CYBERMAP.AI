import HealthStatus from "@/components/HealthStatus";
import { fetchHealth } from "@/lib/api";

/**
 * Server component that performs the live backend health check.
 * Rendered inside <Suspense> on the home page so the check streams in
 * instead of blocking (or breaking) the static shell.
 */
export default async function HealthSection() {
  const health = await fetchHealth();
  return <HealthStatus initial={health} />;
}
