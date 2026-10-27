import "server-only";
import { z } from "zod";
import { lookupRequestSchema, type LookupRequest, type SourceResult } from "../../contracts";
import { fetchProviderJson, ProviderError, safeText, utcDate } from "../http";

const endpoint = "https://api.greynoise.io/v3/community/";
const visualizerOrigin = "https://viz.greynoise.io";

const communityResponseSchema = z.object({
  noise: z.boolean(),
  riot: z.boolean(),
  classification: z.string().trim().min(1).max(40),
  name: z.string().max(180).nullable().optional(),
  last_seen: z.string().max(80).nullable().optional(),
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
    id: "greynoise",
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

function visualizerLink(ip: string, riot: boolean): string {
  const section = riot ? "riot" : "ip";
  return `${visualizerOrigin}/${section}/${ip}`;
}

function findingsFromResponse(data: z.infer<typeof communityResponseSchema>): SourceResult["findings"] {
  const findings: SourceResult["findings"] = [
    {
      label: "GreyNoise noise observation",
      value: data.noise ? "Observed by GreyNoise sensors" : "Not observed by GreyNoise sensors",
      kind: "context",
    },
    {
      label: "GreyNoise RIOT dataset",
      value: data.riot ? "Listed in RIOT" : "Not listed in RIOT",
      kind: "context",
    },
  ];

  const classification = safeText(data.classification, 40);
  const isProviderWarning = ["malicious", "suspicious"].includes(classification.toLowerCase());
  findings.push({
    label: isProviderWarning ? "GreyNoise classification (provider-reported)" : "GreyNoise classification",
    value: classification,
    kind: isProviderWarning ? "warning" : "context",
  });

  const name = data.name ? safeText(data.name, 150) : "";
  if (name) findings.push({ label: "Organization or actor name", value: name, kind: "context" });

  const lastSeen = data.last_seen ? utcDate(data.last_seen) : undefined;
  if (lastSeen) findings.push({ label: "Last seen", value: lastSeen, kind: "context" });

  return findings;
}

/** Look up scanner and RIOT context for a public IPv4 address in GreyNoise Community. */
export async function lookupGreynoise(
  input: LookupRequest,
  key: string = process.env.GREYNOISE_API_KEY ?? "",
  signal?: AbortSignal,
): Promise<SourceResult> {
  if (input.type !== "ip") {
    return result("unsupported", "GreyNoise Community lookup supports public IPv4 addresses only.");
  }
  const parsedInput = lookupRequestSchema.safeParse(input);
  if (!parsedInput.success || parsedInput.data.type !== "ip") {
    return result("unsupported", "GreyNoise Community lookup requires a valid public IPv4 address.");
  }

  const ip = parsedInput.data.value;
  const headers = key.trim() ? { key: key.trim() } : undefined;
  try {
    const raw = await fetchProviderJson(
      `${endpoint}${encodeURIComponent(ip)}`,
      { method: "GET", ...(headers ? { headers } : {}) },
      signal,
    );
    const parsed = communityResponseSchema.safeParse(raw);
    if (!parsed.success) throw new ProviderError("error", "GreyNoise returned an invalid response.");

    const link = visualizerLink(ip, parsed.data.riot);
    const classification = parsed.data.classification.toLowerCase();
    const message = classification === "malicious" || classification === "suspicious"
      ? `GreyNoise reports this IP as ${classification}; scanner and RIOT fields are context and do not independently establish risk.`
      : "GreyNoise returned scanner, RIOT, and classification context. Missing or benign classification does not establish safety.";
    return result("available", message, findingsFromResponse(parsed.data), link);
  } catch (error) {
    if (error instanceof ProviderError) return result(toSourceStatus(error.status), error.message);
    return result("error", "GreyNoise lookup failed.");
  }
}
