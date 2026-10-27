import { z } from "zod";
import type { LookupRequest, SourceResult } from "../../contracts";
import { fetchProviderJson, ProviderError, safeText, utcDate } from "../http";

const endpoint = "https://threatfox-api.abuse.ch/api/v1/";
const coverageNote = "ThreatFox records are limited to the last 6 months.";

const confidenceSchema = z.union([
  z.number().int().min(0).max(100),
  z.string().regex(/^(?:100|[1-9]?\d)$/).transform(Number),
]);

const threatFoxRecordSchema = z
  .object({
    id: z.union([z.string().regex(/^\d{1,12}$/), z.number().int().min(0).max(999_999_999_999)]).transform(String),
    ioc: z.string().trim().min(1).max(500),
    threat_type: z.string().trim().min(1).max(100),
    malware_printable: z.string().trim().max(120).nullable().optional(),
    confidence_level: confidenceSchema.nullable().optional(),
    first_seen: z.string().max(80).nullable().optional(),
    last_seen: z.string().max(80).nullable().optional(),
  })
  .passthrough();

const threatFoxEnvelopeSchema = z
  .object({
    query_status: z.string().trim().min(1).max(80),
    data: z.array(threatFoxRecordSchema).max(100).optional(),
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
  return {
    id: "threatfox",
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

function newestObservation(records: z.infer<typeof threatFoxRecordSchema>[]): string | undefined {
  const dates = records.flatMap((record) => [record.last_seen, record.first_seen]);
  const normalized = dates.map((value) => (value ? utcDate(value) : undefined)).filter(
    (value): value is string => value !== undefined,
  );
  return normalized.sort((left, right) => Date.parse(right) - Date.parse(left))[0];
}

function findingsFromRecords(records: z.infer<typeof threatFoxRecordSchema>[]): SourceResult["findings"] {
  const findings: SourceResult["findings"] = [];
  for (const record of records) {
    const threatType = safeText(record.threat_type, 100);
    findings.push({
      label: "ThreatFox community report",
      value: threatType || "Threat intelligence association reported",
      kind: "warning",
    });

    const malware = record.malware_printable ? safeText(record.malware_printable, 120) : "";
    if (malware) findings.push({ label: "Malware family", value: malware, kind: "context" });

    if (record.confidence_level !== undefined && record.confidence_level !== null) {
      findings.push({
        label: "ThreatFox confidence level",
        value: `${record.confidence_level}/100 (provider-reported)`,
        kind: "context",
      });
    }
    if (findings.length >= 10) break;
  }
  return findings.slice(0, 10);
}

function recordLink(records: z.infer<typeof threatFoxRecordSchema>[]): string | undefined {
  const id = records.find((record) => /^\d{1,12}$/.test(record.id))?.id;
  return id ? `https://threatfox.abuse.ch/ioc/${id}/` : undefined;
}

/** Look up an IP, domain, or MD5/SHA-256 hash in ThreatFox. */
export async function lookupThreatfox(
  input: LookupRequest,
  key: string,
  signal?: AbortSignal,
): Promise<SourceResult> {
  if (input.type === "hash" && input.value.length === 40) {
    return result("unsupported", "ThreatFox hash lookup supports MD5 and SHA-256, not SHA-1.");
  }
  if (input.type === "hash" && input.value.length !== 32 && input.value.length !== 64) {
    return result("unsupported", "ThreatFox hash lookup supports MD5 and SHA-256 hashes.");
  }
  if (!key.trim()) return result("disabled", "ThreatFox is not configured.");

  const body = input.type === "hash"
    ? { query: "search_hash", hash: input.value }
    : { query: "search_ioc", search_term: input.value, exact_match: true };

  try {
    const raw = await fetchProviderJson(
      endpoint,
      {
        method: "POST",
        headers: {
          "Auth-Key": key.trim(),
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      },
      signal,
    );
    const parsed = threatFoxEnvelopeSchema.safeParse(raw);
    if (!parsed.success) throw new ProviderError("error", "ThreatFox returned an invalid response.");

    const status = parsed.data.query_status.toLowerCase();
    if (status === "no_result" || status === "no_results") {
      return result("not_found", `No matching ThreatFox records were found. ${coverageNote}`);
    }
    if (status !== "ok") {
      // Includes provider authentication and permission statuses without exposing response text.
      throw new ProviderError("error", "ThreatFox could not process this indicator.");
    }

    if (parsed.data.data === undefined) throw new ProviderError("error", "ThreatFox returned an invalid response.");
    if (parsed.data.data.length === 0) {
      return result("not_found", `No matching ThreatFox records were found. ${coverageNote}`);
    }

    const records = parsed.data.data;
    const findings = findingsFromRecords(records);
    const count = records.length;
    const message = `ThreatFox reported ${count} community indicator association${count === 1 ? "" : "s"}. ${coverageNote}`;
    return result("available", message, findings, {
      observedAt: newestObservation(records),
      link: recordLink(records),
    });
  } catch (error) {
    if (error instanceof ProviderError) return result(toSourceStatus(error.status), error.message);
    return result("error", "ThreatFox lookup failed.");
  }
}
