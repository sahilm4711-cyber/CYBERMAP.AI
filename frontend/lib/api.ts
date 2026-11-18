import { z } from "zod";

/** Shape of GET /health and GET /api/v1/health (see backend/app/schemas/health.py). */
export const HealthSchema = z.object({
  status: z.string(),
  service: z.string(),
  version: z.string(),
  environment: z.string(),
  timestamp: z.string(),
  database: z.string(),
  ai_mode: z.string(),
});

export type Health = z.infer<typeof HealthSchema>;

export function apiBaseUrl(): string {
  return process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
}

/** Fetch backend health. Returns null when the backend is unreachable. */
export async function fetchHealth(): Promise<Health | null> {
  try {
    const res = await fetch(`${apiBaseUrl()}/api/v1/health`, {
      cache: "no-store",
    });
    if (!res.ok) return null;
    return HealthSchema.parse(await res.json());
  } catch {
    return null;
  }
}
