import { z } from "zod";
import type { LookupRequest, SourceResult } from "../../contracts";
import { fetchProviderJson, ProviderError, safeText, utcDate } from "../http";

const endpoint = "https://urlhaus-api.abuse.ch/v1";
const webHost = "https://urlhaus.abuse.ch/host/";

const countSchema = z.union([
  z.number().int().min(0).max(1_000_000_000),
  z.string().regex(/^\d{1,9}$/).transform(Number),
]);

const urlRecordSchema = z
  .object({
    threat: z.string().max(200).optional(),
    url_status: z.string().max(40).optional(),
    date_added: z.string().max(80).optional(),
  })
  .passthrough();

const urlhausResponseSchema = z
  .object({
    query_status: z.string().trim().min(1).max(64),
    url_count: countSchema.optional(),
    urls_count: countSchema.optional(),
    firstseen: z.string().max(80).nullable().optional(),
    urls: z.array(urlRecordSchema).max(200).optional(),
  })
  .passthrough();

function checkedAt(): string {
  return new Date().toISOString();
}

function result(
  status: SourceResult["status"],
  message: string,
  findings: SourceResult["findings"] = [],
  options: Pick<SourceResult, "observedAt" | "link"> = {},
): SourceResult {
  return { id: "urlhaus", status, message: safeText(message, 500), findings: findings.slice(0, 10), checkedAt: checkedAt(), ...options };
}

function toSourceStatus(status: ProviderError["status"]): SourceResult["status"] {
  if (status === "not_found" || status === "rate_limited" || status === "timeout") return status;
  return "error";
}

function safeHostLink(input: LookupRequest): string | undefined {
  if (input.type !== "ip" && input.type !== "domain") return undefined;
  return `${webHost}${encodeURIComponent(input.value)}/`;
}

function findingsFromResponse(
  count: number,
  firstSeen: string | null | undefined,
  urls: z.infer<typeof urlRecordSchema>[] | undefined,
): SourceResult["findings"] {
  const findings: SourceResult["findings"] = [
    { label: "Associated URLs", value: String(count), kind: "context" },
  ];

  const normalizedFirstSeen = firstSeen ? utcDate(firstSeen) : undefined;
  if (normalizedFirstSeen) {
    findings.push({ label: "First seen", value: normalizedFirstSeen, kind: "context" });
  }

  for (const entry of (urls ?? []).slice(0, 10)) {
    const threat = safeText(entry.threat, 120);
    if (threat) findings.push({ label: "Malware distribution reported", value: threat, kind: "warning" });
    const dateAdded = entry.date_added ? utcDate(entry.date_added) : undefined;
    if (dateAdded) findings.push({ label: "URL added", value: dateAdded, kind: "context" });
    const urlStatus = safeText(entry.url_status, 40);
    if (urlStatus) findings.push({ label: "URL status", value: urlStatus, kind: "context" });
  }
  return findings.slice(0, 10);
}

/** Look up a host or supported payload hash in URLhaus. */
export async function lookupUrlhaus(
  input: LookupRequest,
  key: string,
  signal?: AbortSignal,
): Promise<SourceResult> {
  if (input.type === "hash" && input.value.length === 40) {
    return result("unsupported", "URLhaus payload lookup supports MD5 and SHA-256 hashes, not SHA-1.");
  }
  if (input.type === "hash" && input.value.length !== 32 && input.value.length !== 64) {
    return result("unsupported", "URLhaus payload lookup supports MD5 and SHA-256 hashes.");
  }
  if (!key.trim()) return result("disabled", "URLhaus is not configured.");

  const form = new URLSearchParams();
  let url: string;
  if (input.type === "hash") {
    url = `${endpoint}/payload/`;
    form.set(input.value.length === 32 ? "md5_hash" : "sha256_hash", input.value);
  } else {
    url = `${endpoint}/host/`;
    form.set("host", input.value);
  }

  try {
    const raw = await fetchProviderJson(
      url,
      {
        method: "POST",
        headers: {
          "Auth-Key": key.trim(),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: form,
      },
      signal,
    );
    const parsed = urlhausResponseSchema.safeParse(raw);
    if (!parsed.success) throw new ProviderError("error", "URLhaus returned an invalid response.");

    if (parsed.data.query_status === "no_results") {
      return result("not_found", "URLhaus has no matching malware distribution records.", [], { link: safeHostLink(input) });
    }
    if (parsed.data.query_status !== "ok") {
      throw new ProviderError("error", "URLhaus could not process this indicator.");
    }

    const count = parsed.data.url_count ?? parsed.data.urls_count;
    if (count === undefined) throw new ProviderError("error", "URLhaus returned an invalid response.");

    const observedAt = parsed.data.firstseen ? utcDate(parsed.data.firstseen) : undefined;
    const findings = findingsFromResponse(count, parsed.data.firstseen, parsed.data.urls);
    const message = `URLhaus reported ${count} associated malware distribution URL${count === 1 ? "" : "s"}.`;
    return result("available", message, findings, { observedAt, link: safeHostLink(input) });
  } catch (error) {
    if (error instanceof ProviderError) {
      return result(toSourceStatus(error.status), error.message, [], { link: safeHostLink(input) });
    }
    return result("error", "URLhaus lookup failed.", [], { link: safeHostLink(input) });
  }
}
