import "server-only";
import { z } from "zod";
import { lookupRequestSchema, type LookupRequest, type SourceResult } from "../../contracts";
import { fetchProviderJson, ProviderError, safeText } from "../http";

const endpoint = "https://ipinfo.io/";
const webOrigin = "https://ipinfo.io/";

const ipInfoResponseSchema = z.object({
  org: z.string().max(200).nullable().optional(),
  asn: z.string().max(80).nullable().optional(),
  country: z.string().max(80).nullable().optional(),
  region: z.string().max(120).nullable().optional(),
  city: z.string().max(120).nullable().optional(),
});

function checkedAt(): string {
  return new Date().toISOString();
}

function result(
  status: SourceResult["status"],
  message: string,
  findings: SourceResult["findings"] = [],
  link?: string,
): SourceResult {
  return {
    id: "ipinfo",
    status,
    message: safeText(message, 500),
    findings: findings.slice(0, 10),
    checkedAt: checkedAt(),
    ...(link ? { link } : {}),
  };
}

function toSourceStatus(status: ProviderError["status"]): SourceResult["status"] {
  if (status === "not_found" || status === "rate_limited" || status === "timeout") return status;
  return "error";
}

/** Look up bounded network-owner and location context for a public IPv4 address. */
export async function lookupIpinfo(
  input: LookupRequest,
  token: string = process.env.IPINFO_API_KEY ?? "",
  signal?: AbortSignal,
): Promise<SourceResult> {
  if (input.type !== "ip") return result("unsupported", "IPinfo lookup supports public IPv4 addresses only.");
  const validated = lookupRequestSchema.safeParse(input);
  if (!validated.success || validated.data.type !== "ip") {
    return result("unsupported", "IPinfo lookup requires a valid public IPv4 address.");
  }
  if (!token.trim()) return result("disabled", "IPinfo is not configured.");

  const ip = validated.data.value;
  const link = `${webOrigin}${encodeURIComponent(ip)}`;
  const query = new URLSearchParams({ token: token.trim() });
  try {
    const raw = await fetchProviderJson(
      `${endpoint}${encodeURIComponent(ip)}/json?${query.toString()}`,
      { method: "GET" },
      signal,
    );
    const parsed = ipInfoResponseSchema.safeParse(raw);
    if (!parsed.success) throw new ProviderError("error", "IPinfo returned an invalid response.");

    const fields = parsed.data;
    const findings: SourceResult["findings"] = [];
    const organization = fields.org ? safeText(fields.org, 180) : "";
    if (organization) findings.push({ label: "Organization / ASN", value: organization, kind: "context" });

    const asn = fields.asn ? safeText(fields.asn, 80) : "";
    if (asn) findings.push({ label: "ASN", value: asn, kind: "context" });

    const country = fields.country ? safeText(fields.country, 80) : "";
    if (country) findings.push({ label: "Country", value: country, kind: "context" });

    const region = fields.region ? safeText(fields.region, 120) : "";
    if (region) findings.push({ label: "Region", value: region, kind: "context" });

    const city = fields.city ? safeText(fields.city, 120) : "";
    if (city) findings.push({ label: "City", value: city, kind: "context" });

    const message = findings.length
      ? "IPinfo returned network-owner and geographic context. These fields are not a threat assessment."
      : "IPinfo returned a record without the selected context fields.";
    return result("available", message, findings, link);
  } catch (error) {
    if (error instanceof ProviderError) return result(toSourceStatus(error.status), error.message, [], link);
    return result("error", "IPinfo lookup failed.", [], link);
  }
}
