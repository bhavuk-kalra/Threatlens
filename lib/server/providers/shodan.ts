import "server-only";
import { z } from "zod";
import { lookupRequestSchema, type LookupRequest, type SourceResult } from "../../contracts";
import { fetchProviderJson, ProviderError, safeText, utcDate } from "../http";

const apiEndpoint = "https://api.shodan.io/shodan/host/";
const hostOrigin = "https://www.shodan.io/host/";
const portSchema = z.number().int().min(1).max(65_535);

const serviceSchema = z.object({
  port: portSchema,
  transport: z.string().max(16).nullable().optional(),
  product: z.string().max(200).nullable().optional(),
  data: z.string().max(10_000).nullable().optional(),
});

const shodanResponseSchema = z.object({
  ports: z.array(portSchema).max(1_000),
  data: z.array(serviceSchema).max(1_000),
  last_update: z.string().max(80).nullable().optional(),
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
    id: "shodan",
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

function shodanDate(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  const hasTimezone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(trimmed);
  return utcDate(hasTimezone ? trimmed : `${trimmed}Z`);
}

function serviceSnippet(service: z.infer<typeof serviceSchema>): string {
  const parts = [`${service.port}${service.transport ? `/${safeText(service.transport, 16)}` : ""}`];
  const product = service.product ? safeText(service.product, 100) : "";
  if (product) parts.push(product);
  const banner = service.data ? safeText(service.data, 240) : "";
  if (banner) parts.push(banner);
  return safeText(parts.join(" · "), 400);
}

/** Look up Shodan's historical host exposure context for a public IPv4 address. */
export async function lookupShodan(
  input: LookupRequest,
  key: string = process.env.SHODAN_API_KEY ?? "",
  signal?: AbortSignal,
): Promise<SourceResult> {
  if (input.type !== "ip") return result("unsupported", "Shodan host lookup supports public IPv4 addresses only.");
  const validated = lookupRequestSchema.safeParse(input);
  if (!validated.success || validated.data.type !== "ip") {
    return result("unsupported", "Shodan host lookup requires a valid public IPv4 address.");
  }
  if (!key.trim()) return result("disabled", "Shodan is not configured.");

  const ip = validated.data.value;
  const link = `${hostOrigin}${encodeURIComponent(ip)}`;
  // Shodan requires the API key in the query string for this endpoint; never log this URL.
  const url = `${apiEndpoint}${encodeURIComponent(ip)}?${new URLSearchParams({ key: key.trim() }).toString()}`;
  try {
    const raw = await fetchProviderJson(url, { method: "GET" }, signal);
    const parsed = shodanResponseSchema.safeParse(raw);
    if (!parsed.success) throw new ProviderError("error", "Shodan returned an invalid response.");

    const { ports, data, last_update: lastUpdate } = parsed.data;
    const findings: SourceResult["findings"] = [];
    if (ports.length) {
      const shownPorts = ports.slice(0, 20).join(", ");
      const remainder = ports.length > 20 ? ` (+${ports.length - 20} more)` : "";
      findings.push({
        label: "Ports observed",
        value: `${shownPorts}${remainder}`,
        kind: "context",
      });
    } else {
      findings.push({ label: "Ports observed", value: "No open ports reported in this host record.", kind: "context" });
    }

    for (const service of data.slice(0, 3)) {
      findings.push({ label: "Observed service", value: serviceSnippet(service), kind: "context" });
    }

    const observedAt = shodanDate(lastUpdate);
    if (lastUpdate && !observedAt) throw new ProviderError("error", "Shodan returned an invalid response.");
    if (observedAt) findings.push({ label: "Last scan", value: observedAt, kind: "context" });

    const message = `Shodan returned ${ports.length} observed open port${ports.length === 1 ? "" : "s"} and ${data.length} service record${data.length === 1 ? "" : "s"}. This is exposure context, not malware evidence.`;
    return result("available", message, findings, { observedAt, link });
  } catch (error) {
    if (error instanceof ProviderError) return result(toSourceStatus(error.status), error.message, [], { link });
    return result("error", "Shodan lookup failed.", [], { link });
  }
}
