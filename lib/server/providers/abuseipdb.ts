import "server-only";
import { z } from "zod";
import { lookupRequestSchema, type LookupRequest, type SourceResult } from "../../contracts";
import { fetchProviderJson, ProviderError, safeText, utcDate } from "../http";

const endpoint = "https://api.abuseipdb.com/api/v2/check";
const webOrigin = "https://www.abuseipdb.com/check/";

const abuseIpdbResponseSchema = z.object({
  data: z.object({
    abuseConfidenceScore: z.number().int().min(0).max(100),
    totalReports: z.number().int().min(0).max(1_000_000_000),
    lastReportedAt: z.string().max(80).nullable().optional(),
  }),
});

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
    id: "abuseipdb",
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

/** Look up public IPv4 abuse-report context in AbuseIPDB. */
export async function lookupAbuseipdb(
  input: LookupRequest,
  key: string = process.env.ABUSEIPDB_API_KEY ?? "",
  signal?: AbortSignal,
): Promise<SourceResult> {
  if (input.type !== "ip") return result("unsupported", "AbuseIPDB check lookup supports public IPv4 addresses only.");
  const validated = lookupRequestSchema.safeParse(input);
  if (!validated.success || validated.data.type !== "ip") {
    return result("unsupported", "AbuseIPDB check lookup requires a valid public IPv4 address.");
  }
  if (!key.trim()) return result("disabled", "AbuseIPDB is not configured.");

  const ip = validated.data.value;
  const link = `${webOrigin}${encodeURIComponent(ip)}`;
  const query = new URLSearchParams({ ipAddress: ip, maxAgeInDays: "90" });
  try {
    const raw = await fetchProviderJson(
      `${endpoint}?${query.toString()}`,
      { method: "GET", headers: { Key: key.trim(), Accept: "application/json" } },
      signal,
    );
    const parsed = abuseIpdbResponseSchema.safeParse(raw);
    if (!parsed.success) throw new ProviderError("error", "AbuseIPDB returned an invalid response.");

    const { abuseConfidenceScore, totalReports, lastReportedAt } = parsed.data.data;
    const observedAt = lastReportedAt ? utcDate(lastReportedAt) : undefined;
    const findings: SourceResult["findings"] = [
      {
        label: "AbuseIPDB confidence score (provider-reported)",
        value: `${abuseConfidenceScore}/100`,
        kind: abuseConfidenceScore > 0 ? "warning" : "context",
      },
      { label: "Reports in the last 90 days", value: String(totalReports), kind: "context" },
    ];
    if (observedAt) findings.push({ label: "Last reported", value: observedAt, kind: "context" });

    const message = abuseConfidenceScore > 0
      ? `AbuseIPDB reports a confidence score of ${abuseConfidenceScore}/100 and ${totalReports} reports within the last 90 days.`
      : `AbuseIPDB reports a confidence score of 0/100 and ${totalReports} reports within the last 90 days; this does not establish that the IP is benign.`;
    return result("available", message, findings, { observedAt, link });
  } catch (error) {
    if (error instanceof ProviderError) return result(toSourceStatus(error.status), error.message, [], { link });
    return result("error", "AbuseIPDB lookup failed.", [], { link });
  }
}
