import "server-only";
import { z } from "zod";
import type { LookupRequest, SourceResult } from "../../contracts";
import { fetchProviderJson, ProviderError, safeText, utcDate } from "../http";

const apiEndpoint = "https://otx.alienvault.com/api/v1/indicators";
const webOrigin = "https://otx.alienvault.com";

const countSchema = z.union([
  z.number().int().min(0).max(1_000_000_000),
  z.string().regex(/^\d{1,10}$/).transform(Number),
]);

const pulseSchema = z.object({
  name: z.string().max(200).nullable().optional(),
  tags: z.array(z.string().max(100)).max(50).optional(),
  created: z.string().max(80).nullable().optional(),
  modified: z.string().max(80).nullable().optional(),
});

const otxGeneralSchema = z.object({
  pulse_info: z.object({
    count: countSchema,
    pulses: z.array(pulseSchema).max(100).optional(),
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
    id: "otx",
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

function apiIndicatorType(input: LookupRequest): "IPv4" | "domain" | "file" | undefined {
  if (input.type === "ip" && validIpv4(input.value)) return "IPv4";
  if (input.type === "domain" && validDomain(input.value)) return "domain";
  if (input.type === "hash" && /^(?:[a-f\d]{32}|[a-f\d]{40}|[a-f\d]{64})$/i.test(input.value)) return "file";
  return undefined;
}

function indicatorLink(type: "IPv4" | "domain" | "file", value: string): string {
  const uiType = type === "IPv4" ? "ip" : type;
  return `${webOrigin}/indicator/${uiType}/${encodeURIComponent(value)}`;
}

function communityFindings(pulses: z.infer<typeof pulseSchema>[]): SourceResult["findings"] {
  const findings: SourceResult["findings"] = [];
  for (const pulse of pulses.slice(0, 3)) {
    const name = pulse.name ? safeText(pulse.name, 120) : "";
    if (name) findings.push({ label: "OTX community pulse", value: name, kind: "context" });

    const tags = (pulse.tags ?? []).slice(0, 3).map((tag) => safeText(tag, 60)).filter(Boolean);
    if (tags.length) findings.push({ label: "Pulse tags", value: tags.join(", "), kind: "context" });

    const dateValue = pulse.modified ?? pulse.created;
    const date = dateValue ? utcDate(dateValue) : undefined;
    if (date) findings.push({ label: "Pulse updated", value: date, kind: "context" });
  }
  return findings.slice(0, 9);
}

/** Look up OTX community pulse context for an IP, domain, or file hash. */
export async function lookupOtx(
  input: LookupRequest,
  key: string = process.env.OTX_API_KEY ?? "",
  signal?: AbortSignal,
): Promise<SourceResult> {
  const type = apiIndicatorType(input);
  if (!type) return result("unsupported", "OTX lookup supports valid IPv4 addresses, domains, and MD5/SHA-1/SHA-256 hashes.");
  if (!key.trim()) return result("disabled", "OTX is not configured.");

  const value = input.value.toLowerCase();
  const url = `${apiEndpoint}/${type}/${encodeURIComponent(value)}/general`;
  const link = indicatorLink(type, value);
  try {
    const raw = await fetchProviderJson(url, { method: "GET", headers: { "X-OTX-API-KEY": key.trim() } }, signal);
    const parsed = otxGeneralSchema.safeParse(raw);
    if (!parsed.success) throw new ProviderError("error", "OTX returned an invalid response.");

    const { count, pulses = [] } = parsed.data.pulse_info;
    const findings: SourceResult["findings"] = [
      { label: "Community pulse reports", value: String(count), kind: "context" },
      ...communityFindings(pulses),
    ];
    const message = count === 0
      ? "OTX has no community pulse reports for this indicator; this does not establish that it is benign."
      : `OTX links this indicator to ${count} community pulse report${count === 1 ? "" : "s"}; these reports are community context, not a verdict.`;
    return result("available", message, findings, { link });
  } catch (error) {
    if (error instanceof ProviderError) {
      return result(toSourceStatus(error.status), error.message, [], { link });
    }
    return result("error", "OTX lookup failed.", [], { link });
  }
}
