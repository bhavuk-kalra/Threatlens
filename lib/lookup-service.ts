import { 
  ipAddressSchema, 
  domainSchema, 
  hashSchema, 
  validateInput 
} from "./validation"
import { areRequiredApiKeysConfigured } from "./api-config"

// Custom error class for lookup service
export class LookupError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 500
  ) {
    super(message)
    this.name = "LookupError"
  }
}

// IP lookup function with validation
export async function lookupIP(ip: string) {
  // Validate input
  const validation = validateInput(ipAddressSchema, ip)
  if (!validation.success) {
    throw new LookupError(validation.error, "INVALID_INPUT", 400)
  }

  // Check if required API keys are configured
  if (!areRequiredApiKeysConfigured()) {
    throw new LookupError(
      "API keys not configured. Please configure at least VirusTotal API key for production use.",
      "MISSING_API_KEYS",
      503
    )
  }

  try {
    const response = await fetch("/api/lookup/ip", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ip: validation.data }),
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      throw new LookupError(
        errorData.error || `API error: ${response.status}`,
        "API_ERROR",
        response.status
      )
    }

    const result = await response.json()
    
    // Validate that we have meaningful data
    if (!result || typeof result !== "object") {
      throw new LookupError("Invalid response from API", "INVALID_RESPONSE", 502)
    }

    return result
  } catch (error) {
    if (error instanceof LookupError) {
      throw error
    }
    
    console.error("IP lookup error:", error)
    throw new LookupError(
      "Failed to process IP lookup request",
      "LOOKUP_FAILED",
      500
    )
  }
}

// Domain lookup function with validation
export async function lookupDomain(domain: string) {
  // Validate input
  const validation = validateInput(domainSchema, domain)
  if (!validation.success) {
    throw new LookupError(validation.error, "INVALID_INPUT", 400)
  }

  // Check if required API keys are configured
  if (!areRequiredApiKeysConfigured()) {
    throw new LookupError(
      "API keys not configured. Please configure at least VirusTotal API key for production use.",
      "MISSING_API_KEYS",
      503
    )
  }

  try {
    const response = await fetch("/api/lookup/domain", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ domain: validation.data }),
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      throw new LookupError(
        errorData.error || `API error: ${response.status}`,
        "API_ERROR",
        response.status
      )
    }

    const result = await response.json()
    
    // Validate that we have meaningful data
    if (!result || typeof result !== "object") {
      throw new LookupError("Invalid response from API", "INVALID_RESPONSE", 502)
    }

    return result
  } catch (error) {
    if (error instanceof LookupError) {
      throw error
    }
    
    console.error("Domain lookup error:", error)
    throw new LookupError(
      "Failed to process domain lookup request",
      "LOOKUP_FAILED",
      500
    )
  }
}

// Hash lookup function with validation
export async function lookupHash(hash: string) {
  // Validate input
  const validation = validateInput(hashSchema, hash)
  if (!validation.success) {
    throw new LookupError(validation.error, "INVALID_INPUT", 400)
  }

  // Check if required API keys are configured
  if (!areRequiredApiKeysConfigured()) {
    throw new LookupError(
      "API keys not configured. Please configure at least VirusTotal API key for production use.",
      "MISSING_API_KEYS",
      503
    )
  }

  try {
    const response = await fetch("/api/lookup/hash", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ hash: validation.data }),
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      throw new LookupError(
        errorData.error || `API error: ${response.status}`,
        "API_ERROR",
        response.status
      )
    }

    const result = await response.json()
    
    // Validate that we have meaningful data
    if (!result || typeof result !== "object") {
      throw new LookupError("Invalid response from API", "INVALID_RESPONSE", 502)
    }

    return result
  } catch (error) {
    if (error instanceof LookupError) {
      throw error
    }
    
    console.error("Hash lookup error:", error)
    throw new LookupError(
      "Failed to process hash lookup request",
      "LOOKUP_FAILED",
      500
    )
  }
}

// Helper function to get user-friendly error messages
export function getErrorMessage(error: unknown): string {
  if (error instanceof LookupError) {
    switch (error.code) {
      case "INVALID_INPUT":
        return error.message
      case "MISSING_API_KEYS":
        return "Service temporarily unavailable. Please try again later."
      case "API_ERROR":
        return "External service error. Please try again later."
      case "INVALID_RESPONSE":
        return "Invalid response from service. Please try again later."
      default:
        return "An unexpected error occurred. Please try again later."
    }
  }
  
  if (error instanceof Error) {
    return error.message
  }
  
  return "An unexpected error occurred. Please try again later."
}
