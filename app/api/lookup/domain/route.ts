import { NextRequest, NextResponse } from "next/server"
import { 
  API_ENDPOINTS, 
  getApiKeys, 
  APIError, 
  createFetchWithTimeout, 
  API_TIMEOUTS,
  getRateLimitConfig 
} from "@/lib/api-config"
import { 
  domainLookupRequestSchema, 
  validateInput, 
  createRateLimiter 
} from "@/lib/validation"

// Create rate limiter instance
const rateLimitConfig = getRateLimitConfig()
const rateLimiter = createRateLimiter(rateLimitConfig.windowMs, rateLimitConfig.maxRequests)

export async function POST(request: NextRequest) {
  try {
    // Rate limiting
    const clientIP = request.headers.get("x-forwarded-for") || 
                     request.headers.get("x-real-ip") || 
                     "unknown"
    if (!rateLimiter(clientIP)) {
      return NextResponse.json(
        { error: "Rate limit exceeded. Please try again later." },
        { status: 429 }
      )
    }

    // Parse and validate request body
    const body = await request.json().catch(() => null)
    if (!body) {
      return NextResponse.json(
        { error: "Invalid JSON in request body" },
        { status: 400 }
      )
    }

    const validation = validateInput(domainLookupRequestSchema, body)
    if (!validation.success) {
      return NextResponse.json(
        { error: validation.error },
        { status: 400 }
      )
    }

    const { domain } = validation.data
    const apiKeys = getApiKeys()
    const results: any = { domain }

    // Fetch data from multiple sources in parallel
    const [virusTotalData, whoisData] = await Promise.allSettled([
      fetchVirusTotalData(domain, apiKeys.VIRUSTOTAL_API_KEY),
      fetchWhoisData(domain),
    ])

    // Process results with error handling
    if (virusTotalData.status === "fulfilled" && virusTotalData.value) {
      results.virusTotal = virusTotalData.value
    } else if (virusTotalData.status === "rejected") {
      console.warn("VirusTotal API error:", virusTotalData.reason)
    }

    if (whoisData.status === "fulfilled" && whoisData.value) {
      results.whois = whoisData.value
      results.location = {
        country: whoisData.value.country || "Unknown",
        city: whoisData.value.city || "Unknown",
      }
    } else {
      console.warn("WHOIS API error:", whoisData.status === "rejected" ? whoisData.reason : "No data")
      results.location = {
        country: "Unknown",
        city: "Unknown",
      }
    }

    // Ensure we have at least some data
    const hasData = results.virusTotal || results.whois
    if (!hasData) {
      return NextResponse.json(
        { error: "No data available from any threat intelligence sources" },
        { status: 503 }
      )
    }

    // Calculate threat score and generate findings
    results.threatScore = calculateThreatScore(results)
    results.keyFindings = generateKeyFindings(results)

    return NextResponse.json(results)
  } catch (error) {
    console.error("Domain lookup error:", error)
    
    if (error instanceof APIError) {
      return NextResponse.json(
        { error: error.message },
        { status: error.statusCode }
      )
    }

    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    )
  }
}

async function fetchVirusTotalData(domain: string, apiKey: string | undefined) {
  if (!apiKey) return null

  try {
    const fetchWithTimeout = createFetchWithTimeout(API_TIMEOUTS.VIRUSTOTAL)
    const response = await fetchWithTimeout(`${API_ENDPOINTS.VIRUSTOTAL.DOMAIN}${domain}`, {
      headers: {
        "x-apikey": apiKey,
      },
    })

    if (!response.ok) {
      throw new APIError(`VirusTotal API error: ${response.status}`, response.status, "virustotal")
    }

    const data = await response.json()
    const attributes = data.data.attributes

    // Check if timestamps are valid before returning them
    const firstSeen = attributes.creation_date || null
    const lastSeen = attributes.last_analysis_date || null

    return {
      detectionRatio: `${attributes.last_analysis_stats.malicious}/${Object.keys(attributes.last_analysis_results).length}`,
      firstSeen: firstSeen,
      lastSeen: lastSeen,
      categories: attributes.categories || {},
    }
  } catch (error) {
    if (error instanceof APIError) {
      throw error
    }
    throw new APIError("VirusTotal API request failed", 503, "virustotal", error)
  }
}

async function fetchWhoisData(domain: string) {
  try {
    const fetchWithTimeout = createFetchWithTimeout(API_TIMEOUTS.WHOISJSON)
    const response = await fetchWithTimeout(`${API_ENDPOINTS.WHOISJSON}?domain=${domain}`)
    
    if (!response.ok) {
      throw new APIError(`WHOIS API error: ${response.status}`, response.status, "whois")
    }

    const data = await response.json()

    // Extract relevant information from WHOIS data
    return {
      organization: data.registrant?.organization || data.registrant?.name || "Unknown",
      registrar: data.registrar?.name || "Unknown",
      createdDate: data.created_date || null,
      updatedDate: data.updated_date || null,
      expiresDate: data.expires_date || null,
      nameServers: data.name_servers || [],
      contactEmail: data.registrant?.email || null,
      country: data.registrant?.country || "Unknown",
      city: data.registrant?.city || "Unknown",
    }
  } catch (error) {
    if (error instanceof APIError) {
      throw error
    }
    throw new APIError("WHOIS API request failed", 503, "whois", error)
  }
}

function calculateThreatScore(results: any) {
  let score = 0
  let factors = 0

  // Factor in VirusTotal detections
  if (results.virusTotal?.detectionRatio) {
    const [detected, total] = results.virusTotal.detectionRatio.split("/").map(Number)
    if (total > 0) {
      score += (detected / total) * 100
      factors++
    }
  }

  // Calculate average score
  return factors > 0 ? Math.round(score / factors) : 0
}

function generateKeyFindings(results: any) {
  const findings = []

  // Add domain age
  if (results.virusTotal?.firstSeen) {
    try {
      const firstSeenDate = new Date(results.virusTotal.firstSeen * 1000) // Convert Unix timestamp to milliseconds
      if (!isNaN(firstSeenDate.getTime()) && firstSeenDate.getFullYear() > 1970) {
        const domainAge = Math.floor((Date.now() - firstSeenDate.getTime()) / (1000 * 60 * 60 * 24 * 365))
        if (domainAge >= 0) {
          findings.push(`Domain registered ${domainAge} ${domainAge === 1 ? "year" : "years"} ago`)
        }
      }
    } catch (error) {
      console.warn("Error calculating domain age:", error)
    }
  } else if (results.whois?.createdDate) {
    try {
      const createdDate = new Date(results.whois.createdDate)
      if (!isNaN(createdDate.getTime())) {
        const domainAge = Math.floor((Date.now() - createdDate.getTime()) / (1000 * 60 * 60 * 24 * 365))
        if (domainAge >= 0) {
          findings.push(`Domain registered ${domainAge} ${domainAge === 1 ? "year" : "years"} ago`)
        }
      }
    } catch (error) {
      console.warn("Error calculating domain age from WHOIS:", error)
    }
  }

  // Add threat level finding
  const threatScore = results.threatScore || 0
  if (threatScore >= 80) {
    findings.push("High threat level detected - domain likely malicious")
  } else if (threatScore >= 50) {
    findings.push("Medium threat level detected - domain suspicious")
  } else if (threatScore >= 20) {
    findings.push("Low threat level detected - minor concerns")
  } else {
    findings.push("No malicious activity detected")
  }

  // Add organization info
  if (results.whois?.organization && results.whois.organization !== "Unknown") {
    findings.push(`Registered to ${results.whois.organization}`)
  }

  // Add registrar info
  if (results.whois?.registrar && results.whois.registrar !== "Unknown") {
    findings.push(`Registered through ${results.whois.registrar}`)
  }

  // Add expiration warning if applicable
  if (results.whois?.expiresDate) {
    try {
      const expiresDate = new Date(results.whois.expiresDate)
      if (!isNaN(expiresDate.getTime())) {
        const daysUntilExpiry = Math.floor((expiresDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
        if (daysUntilExpiry < 30 && daysUntilExpiry > 0) {
          findings.push(`Domain expires in ${daysUntilExpiry} days`)
        } else if (daysUntilExpiry <= 0) {
          findings.push("Domain has expired")
        }
      }
    } catch (error) {
      console.warn("Error calculating domain expiry:", error)
    }
  }

  return findings
}
