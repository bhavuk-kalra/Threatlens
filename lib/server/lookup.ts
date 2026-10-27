import "server-only";
import {
  SOURCE_DEFINITIONS,
  sourceResultSchema,
  type LookupRequest,
  type ProviderId,
  type SourceResult,
} from "../contracts";
import { lookupAbuseipdb } from "./providers/abuseipdb";
import { lookupGreynoise } from "./providers/greynoise";
import { lookupIpinfo } from "./providers/ipinfo";
import { lookupMalwarebazaar } from "./providers/malwarebazaar";
import { lookupOtx } from "./providers/otx";
import { lookupShodan } from "./providers/shodan";
import { lookupThreatfox } from "./providers/threatfox";
import { lookupUrlhaus } from "./providers/urlhaus";
import { lookupUrlscan } from "./providers/urlscan";
import { lookupVirustotal } from "./providers/virustotal";

export type ProviderAdapter = (input: LookupRequest, signal?: AbortSignal) => Promise<unknown>;

const providerAdapters: Record<ProviderId, ProviderAdapter> = {
  virustotal: (input, signal) => lookupVirustotal(input, process.env.VIRUSTOTAL_API_KEY ?? "", signal),
  shodan: (input, signal) => lookupShodan(input, process.env.SHODAN_API_KEY ?? "", signal),
  abuseipdb: (input, signal) => lookupAbuseipdb(input, process.env.ABUSEIPDB_API_KEY ?? "", signal),
  ipinfo: (input, signal) => lookupIpinfo(input, process.env.IPINFO_API_KEY ?? "", signal),
  urlhaus: (input, signal) => lookupUrlhaus(input, process.env.ABUSECH_AUTH_KEY ?? "", signal),
  threatfox: (input, signal) => lookupThreatfox(input, process.env.ABUSECH_AUTH_KEY ?? "", signal),
  malwarebazaar: (input, signal) => lookupMalwarebazaar(input, process.env.ABUSECH_AUTH_KEY ?? "", signal),
  urlscan: (input, signal) => lookupUrlscan(input, process.env.URLSCAN_API_KEY ?? "", signal),
  otx: (input, signal) => lookupOtx(input, process.env.OTX_API_KEY ?? "", signal),
  greynoise: (input, signal) => lookupGreynoise(input, process.env.GREYNOISE_API_KEY ?? "", signal),
};

function failedResult(id: ProviderId, message: string): SourceResult {
  return {
    id,
    status: "error",
    message,
    findings: [],
    checkedAt: new Date().toISOString(),
  };
}

export function normalizeProviderResult(id: ProviderId, value: unknown): SourceResult {
  const parsed = sourceResultSchema.safeParse(value);
  if (!parsed.success || parsed.data.id !== id) {
    return failedResult(id, `${SOURCE_DEFINITIONS[id].name} returned an invalid result.`);
  }
  return parsed.data;
}

export async function lookupSelectedSources(
  input: LookupRequest,
  sourceIds: ProviderId[],
  signal?: AbortSignal,
  adapters: Partial<Record<ProviderId, ProviderAdapter>> = providerAdapters,
): Promise<SourceResult[]> {
  const selected = sourceIds.slice(0, 10);
  return Promise.all(selected.map(async (id) => {
    const adapter = adapters[id];
    if (!adapter) return failedResult(id, `${SOURCE_DEFINITIONS[id].name} lookup is unavailable.`);
    try {
      return normalizeProviderResult(id, await adapter(input, signal));
    } catch {
      return failedResult(id, `${SOURCE_DEFINITIONS[id].name} lookup failed.`);
    }
  }));
}
