import { z } from "zod";

export const providerIds = [
  "virustotal",
  "shodan",
  "abuseipdb",
  "ipinfo",
  "urlhaus",
  "threatfox",
  "malwarebazaar",
  "urlscan",
  "otx",
  "greynoise",
] as const;

export const lookupTypes = ["ip", "domain", "hash"] as const;

export type ProviderId = (typeof providerIds)[number];
export type LookupType = (typeof lookupTypes)[number];
export type ProviderGroup = "reputation" | "malware" | "infrastructure" | "community";

export const SOURCE_DEFINITIONS = {
  virustotal: {
    name: "VirusTotal",
    description: "Aggregated reputation and analysis for network indicators and file hashes.",
    group: "reputation",
    supportedTypes: ["ip", "domain", "hash"],
  },
  shodan: {
    name: "Shodan",
    description: "Internet exposure and service context for an IP address.",
    group: "infrastructure",
    supportedTypes: ["ip"],
  },
  abuseipdb: {
    name: "AbuseIPDB",
    description: "Community abuse reports and confidence data for an IP address.",
    group: "reputation",
    supportedTypes: ["ip"],
  },
  ipinfo: {
    name: "IPinfo",
    description: "Network ownership and geographic context for an IP address.",
    group: "infrastructure",
    supportedTypes: ["ip"],
  },
  urlhaus: {
    name: "URLhaus",
    description: "Malware distribution activity associated with an indicator.",
    group: "malware",
    supportedTypes: ["ip", "domain", "hash"],
  },
  threatfox: {
    name: "ThreatFox",
    description: "Community malware and threat intelligence for an indicator.",
    group: "community",
    supportedTypes: ["ip", "domain", "hash"],
  },
  malwarebazaar: {
    name: "MalwareBazaar",
    description: "Malware sample intelligence for a supported file hash.",
    group: "malware",
    supportedTypes: ["hash"],
  },
  urlscan: {
    name: "urlscan.io",
    description: "Public scan context for an IP address or domain.",
    group: "community",
    supportedTypes: ["ip", "domain"],
  },
  otx: {
    name: "LevelBlue OTX",
    description: "Open threat intelligence pulse context for an indicator.",
    group: "community",
    supportedTypes: ["ip", "domain", "hash"],
  },
  greynoise: {
    name: "GreyNoise",
    description: "Internet scanner and noise context for an IP address.",
    group: "reputation",
    supportedTypes: ["ip"],
  },
} as const satisfies Record<
  ProviderId,
  { name: string; description: string; group: ProviderGroup; supportedTypes: readonly LookupType[] }
>;

const lookupTypeSchema = z.enum(lookupTypes);
const providerIdSchema = z.enum(providerIds);

function parseIpv4(value: string): number[] | null {
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^(?:0|[1-9]\d{0,2})$/.test(part))) return null;
  const octets = parts.map(Number);
  return octets.every((octet) => octet >= 0 && octet <= 255) ? octets : null;
}

function isPublicIpv4(value: string): boolean {
  const octets = parseIpv4(value);
  if (!octets) return false;
  const address = (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]);
  const inRange = (start: string, end: string) => {
    const toNumber = (ip: string) => parseIpv4(ip)!.reduce((result, octet) => result * 256 + octet, 0);
    return address >= toNumber(start) && address <= toNumber(end);
  };

  const reservedRanges: ReadonlyArray<readonly [string, string]> = [
    ["0.0.0.0", "0.255.255.255"],
    ["10.0.0.0", "10.255.255.255"],
    ["100.64.0.0", "100.127.255.255"],
    ["127.0.0.0", "127.255.255.255"],
    ["169.254.0.0", "169.254.255.255"],
    ["172.16.0.0", "172.31.255.255"],
    ["192.0.0.0", "192.0.0.255"],
    ["192.0.2.0", "192.0.2.255"],
    ["192.88.99.0", "192.88.99.255"],
    ["192.168.0.0", "192.168.255.255"],
    ["198.18.0.0", "198.19.255.255"],
    ["198.51.100.0", "198.51.100.255"],
    ["203.0.113.0", "203.0.113.255"],
    ["224.0.0.0", "255.255.255.255"],
  ];
  return !reservedRanges.some(([start, end]) => inRange(start, end));
}

function isDomain(value: string): boolean {
  if (value.length > 253 || !value.includes(".") || value.endsWith(".")) return false;
  if (parseIpv4(value) || value.includes(":")) return false;
  const labels = value.split(".");
  const tld = labels[labels.length - 1];
  if (!tld || /^\d+$/.test(tld) || tld.length < 2) return false;
  return labels.every(
    (label) => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
  );
}

const hashPattern = /^(?:[a-f\d]{32}|[a-f\d]{40}|[a-f\d]{64})$/i;

export const lookupRequestSchema = z
  .object({
    type: lookupTypeSchema,
    value: z.string().trim().min(1).max(253),
    sourceIds: z.array(providerIdSchema).min(1).max(providerIds.length).optional(),
  })
  .strict()
  .superRefine(({ type, value, sourceIds }, ctx) => {
    if (type === "ip" && !isPublicIpv4(value)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["value"], message: "Enter a public IPv4 address." });
    }
    if (type === "domain" && !isDomain(value.toLowerCase())) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["value"], message: "Enter a domain name without a URL, port, or IP address." });
    }
    if (type === "hash" && !hashPattern.test(value)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["value"], message: "Enter an MD5, SHA-1, or SHA-256 hash." });
    }
    if (sourceIds && new Set(sourceIds).size !== sourceIds.length) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["sourceIds"], message: "Source IDs must be unique." });
    }
  })
  .transform((request) => ({
    ...request,
    value: request.type === "ip" ? request.value : request.value.toLowerCase(),
  }));

export const findingSchema = z
  .object({
    label: z.string().trim().min(1).max(100),
    value: z.string().trim().max(500),
    kind: z.enum(["warning", "context", "neutral"]),
  })
  .strict();

export const sourceResultSchema = z
  .object({
    id: providerIdSchema,
    status: z.enum(["available", "not_found", "disabled", "unsupported", "rate_limited", "timeout", "error"]),
    message: z.string().trim().max(500),
    findings: z.array(findingSchema).max(50),
    checkedAt: z.string().datetime(),
    observedAt: z.string().datetime().optional(),
    link: z.string().url().refine((value) => value.startsWith("https://"), "Link must use HTTPS.").optional(),
  })
  .strict();

export const lookupResultSchema = z
  .object({
    type: lookupTypeSchema,
    value: z.string().trim().min(1).max(253),
    lookedUpAt: z.string().datetime(),
    mode: z.literal("live"),
    sources: z.array(sourceResultSchema).max(providerIds.length),
  })
  .strict();

export type LookupRequest = z.infer<typeof lookupRequestSchema>;
export type Finding = z.infer<typeof findingSchema>;
export type SourceResult = z.infer<typeof sourceResultSchema>;
export type LookupResult = z.infer<typeof lookupResultSchema>;
