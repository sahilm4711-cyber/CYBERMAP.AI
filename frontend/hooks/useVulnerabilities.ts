import { useQuery } from "@tanstack/react-query";
import {
  fetchVulnerabilities,
  fetchVulnerabilityDetail,
  type VulnerabilityFilters,
} from "@/lib/services/vulnerabilities";

export function useVulnerabilities(filters: VulnerabilityFilters) {
  return useQuery({
    queryKey: ["vulnerabilities", filters],
    queryFn: () => fetchVulnerabilities(filters),
  });
}

export function useVulnerabilityDetail(cveId: string) {
  return useQuery({
    queryKey: ["vulnerability", cveId],
    queryFn: () => fetchVulnerabilityDetail(cveId),
    enabled: cveId.length > 0,
  });
}
