import "server-only";
import { z } from "zod";
import { lookupRequestSchema, type LookupRequest, type SourceResult } from "../../contracts";
import { fetchProviderJson, ProviderError, safeText, utcDate } from "../http";

const apiOrigin = "https://www.virustotal.com/api/v3";
const guiOrigin = "https://www.virustotal.com/gui";
const countSchema = z.number().int().min(0).max(1_000_000_000);
const timestampSchema = z.number().int().min(0).max(253_402_300_799).nullable().optional();

const analysisStatsSchema = z.object({
  malicious: countSchema.optional(),
  suspicious: countSchema.optional(),
  harmless: countSchema.optional(),
  undetected: countSchema.optional(),
  timeout: countSchema.optional(),
  "confirmed-timeout": countSchema.optional(),
  failure: countSchema.optional(),
  "type-unsupported": countSchema.optional(),
});

const virusTotalResponseSchema = z.object({
  data: z.object({
    attributes: z.object({
      last_analysis_stats: analysisStatsSchema.nullable().optional(),
      last_analysis_date: timestampSchema,
    }),
  }),
});

type AnalysisStats = z.infer<typeof analysisStatsSchema>;

function checkedAt(): string {
  return new Date().toISOString();
}

function result(
  status: SourceResult["status"],
  message: string,
  findings: SourceResult["findings"] = [],
  options: Pick<SourceResult, "observedAt" | "link"> = {},
): SourceResult {
  return {
    id: "virustotal",
    status,
    message: safeText(message, 500),
    findings: findings.slice(0, 10),
    checkedAt: checkedAt(),
    ...options,
  };
}

function toSourceStatus(status: ProviderError["status"]): SourceResult["status"] {
  if (status === "not_found" || status === "rate_limited" || status === "timeout") return status;
  return "error";
}

function endpointFor(input: LookupRequest): { url: string; link: string } | undefined {
  if (input.type === "ip") {
    return {
      url: `${apiOrigin}/ip_addresses/${encodeURIComponent(input.value)}`,
      link: `${guiOrigin}/ip-address/${encodeURIComponent(input.value)}`,
    };
  }
  if (input.type === "domain") {
    return {
      url: `${apiOrigin}/domains/${encodeURIComponent(input.value)}`,
      link: `${guiOrigin}/domain/${encodeURIComponent(input.value)}`,
    };
  }
  if (/^(?:[a-f\d]{32}|[a-f\d]{40}|[a-f\d]{64})$/i.test(input.value)) {
    return {
      url: `${apiOrigin}/files/${encodeURIComponent(input.value)}`,
      link: `${guiOrigin}/file/${encodeURIComponent(input.value)}`,
    };
  }
  return undefined;
}

function statsTotal(stats: AnalysisStats): number {
  return Object.values(stats).reduce((sum, value) => sum + (value ?? 0), 0);
}

function timestamp(value: number | null | undefined): string | undefined {
  return value === undefined || value === null ? undefined : utcDate(value * 1000);
}

/** Look up an IP, domain, or supported file hash in VirusTotal v3. */
export async function lookupVirustotal(
  input: LookupRequest,
  key: string = process.env.VIRUSTOTAL_API_KEY ?? "",
  signal?: AbortSignal,
): Promise<SourceResult> {
  const validated = lookupRequestSchema.safeParse(input);
  const target = validated.success ? endpointFor(validated.data) : undefined;
  if (!target) return result("unsupported", "VirusTotal supports valid IPv4 addresses, domains, and MD5/SHA-1/SHA-256 hashes.");
  if (!key.trim()) return result("disabled", "VirusTotal is not configured.", [], { link: target.link });

  try {
    const raw = await fetchProviderJson(target.url, { method: "GET", headers: { "x-apikey": key.trim() } }, signal);
    const parsed = virusTotalResponseSchema.safeParse(raw);
    if (!parsed.success) throw new ProviderError("error", "VirusTotal returned an invalid response.");

    const { last_analysis_stats: stats, last_analysis_date: rawAnalysisDate } = parsed.data.data.attributes;
    const observedAt = timestamp(rawAnalysisDate);
    const findings: SourceResult["findings"] = [];
    const hasStats = stats !== undefined && stats !== null && Object.keys(stats).length > 0;
    const total = hasStats ? statsTotal(stats) : 0;
    if (!hasStats || total === 0) {
      findings.push({
        label: "Analysis statistics",
        value: "No engine results reported for this record.",
        kind: "context",
      });
    } else {
      const malicious = stats.malicious ?? 0;
      const suspicious = stats.suspicious ?? 0;
      const detections = malicious + suspicious;
      findings.push({
        label: "Detections reported",
        value: `${malicious} malicious, ${suspicious} suspicious`,
        kind: detections > 0 ? "warning" : "context",
      });
      findings.push({ label: "Engine results", value: String(total), kind: "context" });
    }
    if (observedAt) findings.push({ label: "Last analysis", value: observedAt, kind: "context" });

    const message = !hasStats || total === 0
      ? "VirusTotal returned a record without engine results; there is insufficient analysis evidence."
      : stats.malicious || stats.suspicious
        ? `VirusTotal analysis reported ${stats.malicious ?? 0} malicious and ${stats.suspicious ?? 0} suspicious detections.`
        : `VirusTotal reported no malicious or suspicious detections among ${total} engine results. Absence of detections does not establish benignness.`;
    return result("available", message, findings, { observedAt, link: target.link });
  } catch (error) {
    if (error instanceof ProviderError) {
      return result(toSourceStatus(error.status), error.message, [], { link: target.link });
    }
    return result("error", "VirusTotal lookup failed.", [], { link: target.link });
  }
}
