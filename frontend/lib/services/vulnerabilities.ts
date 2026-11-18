import { z } from "zod";
import { apiGet, toQuery } from "@/lib/services/client";

/** Zod schemas mirror backend/app/schemas/vulnerabilities.py. */

export const VulnerabilityListItemSchema = z.object({
  cve_id: z.string(),
  title: z.string().nullable(),
  severity: z.string().nullable(),
  cvss_score: z.number().nullable(),
  cvss_version: z.string().nullable(),
  epss_score: z.number().nullable(),
  epss_percentile: z.number().nullable(),
  is_kev: z.boolean(),
  cwe_ids: z.array(z.string()),
  published_at: z.string().nullable(),
});

export const VulnerabilityListResponseSchema = z.object({
  items: z.array(VulnerabilityListItemSchema),
  total: z.number(),
  page: z.number(),
  per_page: z.number(),
  pages: z.number(),
});

export const VulnerabilityDetailSchema = z.object({
  cve_id: z.string(),
  title: z.string().nullable(),
  description: z.string(),
  cvss_score: z.number().nullable(),
  cvss_version: z.string().nullable(),
  cvss_vector: z.string().nullable(),
  severity: z.string().nullable(),
  published_at: z.string().nullable(),
  last_modified_at: z.string().nullable(),
  source: z.string(),
  source_url: z.string().nullable(),
  cwes: z.array(
    z.object({
      cwe_id: z.string(),
      name: z.string(),
      description: z.string().nullable(),
    }),
  ),
  affected_products: z.array(
    z.object({
      vendor: z.string().nullable(),
      product: z.string().nullable(),
      version_start: z.string().nullable(),
      version_end: z.string().nullable(),
      version_range_text: z.string().nullable(),
    }),
  ),
  references: z.array(
    z.object({ url: z.string(), source: z.string().nullable() }),
  ),
  epss: z
    .object({
      epss_score: z.number(),
      percentile: z.number(),
      model_date: z.string(),
    })
    .nullable(),
  kev: z
    .object({
      vendor_project: z.string().nullable(),
      product: z.string().nullable(),
      vulnerability_name: z.string().nullable(),
      date_added: z.string().nullable(),
      due_date: z.string().nullable(),
      short_description: z.string().nullable(),
      required_action: z.string().nullable(),
      ransomware_use: z.string().nullable(),
    })
    .nullable(),
  related: z.array(
    z.object({
      cve_id: z.string(),
      title: z.string().nullable(),
      severity: z.string().nullable(),
      cvss_score: z.number().nullable(),
      published_at: z.string().nullable(),
    }),
  ),
  remediation: z.string().nullable(),
});

export const RelatedVulnerabilitySchema = z.object({
  cve_id: z.string(),
  title: z.string().nullable(),
  severity: z.string().nullable(),
  cvss_score: z.number().nullable(),
  published_at: z.string().nullable(),
});

export type VulnerabilityListItem = z.infer<typeof VulnerabilityListItemSchema>;
export type VulnerabilityListResponse = z.infer<
  typeof VulnerabilityListResponseSchema
>;
export type VulnerabilityDetail = z.infer<typeof VulnerabilityDetailSchema>;

export type VulnerabilitySort =
  | "newest"
  | "oldest"
  | "severity"
  | "cvss"
  | "epss"
  | "risk";

export interface VulnerabilityFilters {
  q?: string;
  severity?: string[];
  cwe?: string;
  min_cvss?: number;
  max_cvss?: number;
  min_epss?: number;
  max_epss?: number;
  vendor?: string;
  product?: string;
  kev_only?: boolean;
  published_from?: string;
  published_to?: string;
  sort?: VulnerabilitySort;
  page?: number;
  per_page?: number;
}

export async function fetchVulnerabilities(
  filters: VulnerabilityFilters = {},
): Promise<VulnerabilityListResponse> {
  const json = await apiGet<unknown>(
    `/api/v1/vulnerabilities${toQuery(filters)}`,
  );
  return VulnerabilityListResponseSchema.parse(json);
}

export async function fetchVulnerabilityDetail(
  cveId: string,
): Promise<VulnerabilityDetail> {
  const json = await apiGet<unknown>(
    `/api/v1/vulnerabilities/${encodeURIComponent(cveId)}`,
  );
  return VulnerabilityDetailSchema.parse(json);
}
