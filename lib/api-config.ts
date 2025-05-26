import { envSchema, type EnvConfig } from "./validation"

// API endpoints configuration
export const API_ENDPOINTS = {
  SHODAN: "https://api.shodan.io/shodan/host/",
  VIRUSTOTAL: {
    IP: "https://www.virustotal.com/api/v3/ip_addresses/",
    DOMAIN: "https://www.virustotal.com/api/v3/domains/",
    FILE: "https://www.virustotal.com/api/v3/files/",
  },
  ABUSEIPDB: "https://api.abuseipdb.com/api/v2/check",
  IPINFO: "https://ipinfo.io/",
  WHOISJSON: "https://whoisjson.com/api/v1/whois",
} as const

// Validate and get environment configuration
export function getValidatedEnv(): EnvConfig {
  try {
    return envSchema.parse(process.env)
  } catch (error) {
    console.error("Environment validation failed:", error)
    throw new Error("Invalid environment configuration")
  }
}

// Get API keys with validation
export function getApiKeys() {
  const env = getValidatedEnv()
  return {
    SHODAN_API_KEY: env.SHODAN_API_KEY,
    VIRUSTOTAL_API_KEY: env.VIRUSTOTAL_API_KEY,
    ABUSEIPDB_API_KEY: env.ABUSEIPDB_API_KEY,
    IPINFO_API_KEY: env.IPINFO_API_KEY,
  }
}

// Check if required API keys are configured for production
export function areRequiredApiKeysConfigured(): boolean {
  const keys = getApiKeys()
  const env = getValidatedEnv()
  
  // In production, require at least VirusTotal API key
  if (env.NODE_ENV === "production") {
    return !!(keys.VIRUSTOTAL_API_KEY)
  }
  
  // In development, allow running without API keys for testing
  return true
}

// Check which API keys are configured
export function areApiKeysConfigured() {
  const keys = getApiKeys()
  return {
    shodan: !!keys.SHODAN_API_KEY,
    virusTotal: !!keys.VIRUSTOTAL_API_KEY,
    abuseIPDB: !!keys.ABUSEIPDB_API_KEY,
    ipInfo: !!keys.IPINFO_API_KEY,
  }
}

// API timeout configuration
export const API_TIMEOUTS = {
  SHODAN: 10000, // 10 seconds
  VIRUSTOTAL: 15000, // 15 seconds
  ABUSEIPDB: 8000, // 8 seconds
  IPINFO: 5000, // 5 seconds
  WHOISJSON: 10000, // 10 seconds
} as const

// Rate limiting configuration
export function getRateLimitConfig() {
  const env = getValidatedEnv()
  return {
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    maxRequests: env.RATE_LIMIT_MAX_REQUESTS,
  }
}

// API error types
export class APIError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public service: string,
    public originalError?: unknown
  ) {
    super(message)
    this.name = "APIError"
  }
}

// Helper function to create fetch with timeout
export function createFetchWithTimeout(timeoutMs: number) {
  return async (url: string, options?: RequestInit): Promise<Response> => {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs)
    
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      })
      clearTimeout(timeoutId)
      return response
    } catch (error) {
      clearTimeout(timeoutId)
      if (error instanceof Error && error.name === "AbortError") {
        throw new APIError(`Request timeout after ${timeoutMs}ms`, 408, "timeout")
      }
      throw error
    }
  }
}
