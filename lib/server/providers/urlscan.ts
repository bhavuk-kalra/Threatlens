import "server-only";
import { z } from "zod";
import type { LookupRequest, SourceResult } from "../../contracts";
import { fetchProviderJson, ProviderError, safeText, utcDate } from "../http";

const endpoint = "https://urlscan.io/api/v1/search";
const uuidPattern = /^[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}$/i;

const taskSchema = z.object({
  uuid: z.string().trim().min(1).max(80),
  time: z.string().trim().min(1).max(80),
});

const scanResultSchema = z.object({
  task: taskSchema,
  page: z.object({
    domain: z.string().max(253).optional(),
    ip: z.string().max(64).optional(),
    status: z.union([z.string().max(40), z.number().int().min(0).max(999)]).optional(),
  }).optional(),
});

const searchResponseSchema = z.object({
  results: z.array(scanResultSchema).max(5),
  total: z.number().int().min(0).max(1_000_000_000),
  has_more: z.boolean().optional(),
  search_date_limit_days: z.number().int().min(0).max(100_000).optional(),
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
    id: "urlscan",
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

function validIpv4(value: string): boolean {
  const octets = value.split(".");
  return octets.length === 4 && octets.every((octet) => /^(?:0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255);
}

function validDomain(value: string): boolean {
  if (value.length > 253 || !value.includes(".")) return false;
  return value.split(".").every((label) =>
    label.length > 0 && label.length <= 63 && /^[a-z\d](?:[a-z\d-]*[a-z\d])?$/i.test(label),
  );
}

function scanMetadata(scan: z.infer<typeof scanResultSchema>): string | undefined {
  const parts: string[] = [];
  const domain = scan.page?.domain ? safeText(scan.page.domain, 253) : "";
  const ip = scan.page?.ip ? safeText(scan.page.ip, 64) : "";
  const pageStatus = scan.page?.status === undefined ? "" : safeText(scan.page.status, 40);
  if (domain) parts.push(`domain ${domain}`);
  if (ip) parts.push(`IP ${ip}`);
  if (pageStatus) parts.push(`HTTP ${pageStatus}`);
  return parts.length ? parts.join(" · ") : undefined;
}

/** Search up to five recent historical urlscan.io scans for an IP or domain. */
export async function lookupUrlscan(
  input: LookupRequest,
  key: string = process.env.URLSCAN_API_KEY ?? "",
  signal?: AbortSignal,
): Promise<SourceResult> {
  if (input.type !== "ip" && input.type !== "domain") {
    return result("unsupported", "urlscan.io historical search supports IP addresses and domains only.");
  }
  if (input.type === "ip" ? !validIpv4(input.value) : !validDomain(input.value)) {
    return result("unsupported", "urlscan.io search requires a valid IP address or domain.");
  }
  if (!key.trim()) return result("disabled", "urlscan.io is not configured.");

  const params = new URLSearchParams({
    q: `${input.type === "ip" ? "page.ip" : "page.domain"}:${input.value}`,
    size: "5",
  });
  try {
    const raw = await fetchProviderJson(
      `${endpoint}?${params.toString()}`,
      { method: "GET", headers: { "api-key": key.trim() } },
      signal,
    );
    const parsed = searchResponseSchema.safeParse(raw);
    if (!parsed.success) throw new ProviderError("error", "urlscan.io returned an invalid response.");

    const { results, total, has_more: hasMore, search_date_limit_days: dateLimitDays } = parsed.data;
    if (results.length === 0) {
      if (total !== 0) throw new ProviderError("error", "urlscan.io returned an invalid response.");
      const limit = dateLimitDays === undefined ? "" : ` Search history is limited to the last ${dateLimitDays} days for this account.`;
      return result("not_found", `No historical urlscan.io scans matched this indicator.${limit}`);
    }

    const findings: SourceResult["findings"] = [
      { label: "Historical scan count", value: `${total}${hasMore ? "+" : ""}`, kind: "context" },
    ];
    for (const scan of results) {
      const observedAt = utcDate(scan.task.time);
      if (!observedAt) throw new ProviderError("error", "urlscan.io returned an invalid response.");
      const metadata = scanMetadata(scan);
      findings.push({
        label: "Historical scan",
        value: safeText(`${observedAt}${metadata ? ` · ${metadata}` : ""}`, 500),
        kind: "context",
      });
    }

    const newestScan = results[0];
    const observedAt = utcDate(newestScan.task.time);
    const link = uuidPattern.test(newestScan.task.uuid)
      ? `https://urlscan.io/result/${newestScan.task.uuid.toLowerCase()}/`
      : undefined;
    const count = `${total}${hasMore ? "+" : ""}`;
    const limit = dateLimitDays === undefined ? "" : ` Search history is limited to the last ${dateLimitDays} days for this account.`;
    return result(
      "available",
      `urlscan.io found ${count} historical scan${total === 1 ? "" : "s"}. These records provide scan context, not a maliciousness verdict.${limit}`,
      findings,
      { observedAt, link },
    );
  } catch (error) {
    if (error instanceof ProviderError) return result(toSourceStatus(error.status), error.message);
    return result("error", "urlscan.io lookup failed.");
  }
}
