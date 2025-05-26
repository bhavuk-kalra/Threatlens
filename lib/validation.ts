import { z } from "zod"

// IP Address validation schema
export const ipAddressSchema = z.string()
  .min(7, "IP address must be at least 7 characters")
  .max(15, "IP address must be at most 15 characters")
  .regex(
    /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
    "Invalid IP address format"
  )
  .refine((ip) => {
    // Additional validation for private/reserved IP ranges
    const parts = ip.split('.').map(Number)
    const firstOctet = parts[0]
    const secondOctet = parts[1]
    
    // Reject localhost
    if (firstOctet === 127) return false
    
    // Reject multicast and reserved ranges
    if (firstOctet >= 224) return false
    
    // Reject 0.0.0.0/8
    if (firstOctet === 0) return false
    
    return true
  }, "Invalid or reserved IP address")

// Domain validation schema
export const domainSchema = z.string()
  .min(1, "Domain is required")
  .max(253, "Domain name too long")
  .regex(
    /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/,
    "Invalid domain format"
  )
  .refine((domain) => {
    // Must contain at least one dot for TLD
    if (!domain.includes('.')) return false
    
    // Check TLD length (2-63 characters)
    const tld = domain.split('.').pop()
    if (!tld || tld.length < 2 || tld.length > 63) return false
    
    // Reject domains starting or ending with hyphen
    if (domain.startsWith('-') || domain.endsWith('-')) return false
    
    // Each label must not start or end with hyphen
    const labels = domain.split('.')
    for (const label of labels) {
      if (label.startsWith('-') || label.endsWith('-')) return false
      if (label.length > 63) return false
    }
    
    return true
  }, "Invalid domain name")

// Hash validation schema (supports MD5, SHA-1, SHA-256, SHA-512)
export const hashSchema = z.string()
  .min(32, "Hash must be at least 32 characters (MD5)")
  .max(128, "Hash must be at most 128 characters (SHA-512)")
  .regex(/^[a-fA-F0-9]+$/, "Hash must contain only hexadecimal characters")
  .refine((hash) => {
    const length = hash.length
    // Valid hash lengths: MD5 (32), SHA-1 (40), SHA-256 (64), SHA-512 (128)
    return [32, 40, 64, 128].includes(length)
  }, "Invalid hash length. Must be MD5 (32), SHA-1 (40), SHA-256 (64), or SHA-512 (128) characters")

// API request schemas
export const ipLookupRequestSchema = z.object({
  ip: ipAddressSchema
})

export const domainLookupRequestSchema = z.object({
  domain: domainSchema
})

export const hashLookupRequestSchema = z.object({
  hash: hashSchema
})

// Type exports
export type IPLookupRequest = z.infer<typeof ipLookupRequestSchema>
export type DomainLookupRequest = z.infer<typeof domainLookupRequestSchema>
export type HashLookupRequest = z.infer<typeof hashLookupRequestSchema>

// Validation helper function
export function validateInput<T>(schema: z.ZodSchema<T>, data: unknown): { success: true; data: T } | { success: false; error: string } {
  try {
    const result = schema.parse(data)
    return { success: true, data: result }
  } catch (error) {
    if (error instanceof z.ZodError) {
      const firstError = error.errors[0]
      return { success: false, error: firstError.message }
    }
    return { success: false, error: "Validation failed" }
  }
}

// Rate limiting helper
export function createRateLimiter(windowMs: number, maxRequests: number) {
  const requests = new Map<string, number[]>()
  
  return (identifier: string): boolean => {
    const now = Date.now()
    const windowStart = now - windowMs
    
    if (!requests.has(identifier)) {
      requests.set(identifier, [])
    }
    
    const userRequests = requests.get(identifier)!
    
    // Remove old requests outside the window
    const validRequests = userRequests.filter(time => time > windowStart)
    
    if (validRequests.length >= maxRequests) {
      return false
    }
    
    validRequests.push(now)
    requests.set(identifier, validRequests)
    
    return true
  }
}

// Environment validation
export const envSchema = z.object({
  SHODAN_API_KEY: z.string().min(1, "Shodan API key is required").optional(),
  VIRUSTOTAL_API_KEY: z.string().min(1, "VirusTotal API key is required").optional(),
  ABUSEIPDB_API_KEY: z.string().min(1, "AbuseIPDB API key is required").optional(),
  IPINFO_API_KEY: z.string().min(1, "IPInfo API key is required").optional(),
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  RATE_LIMIT_WINDOW_MS: z.string().transform(Number).default("900000"), // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: z.string().transform(Number).default("100"),
})

export type EnvConfig = z.infer<typeof envSchema>
