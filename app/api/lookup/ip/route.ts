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
  ipLookupRequestSchema, 
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

    const validation = validateInput(ipLookupRequestSchema, body)
    if (!validation.success) {
      return NextResponse.json(
        { error: validation.error },
        { status: 400 }
      )
    }

    const { ip } = validation.data
    const apiKeys = getApiKeys()
    const results: any = { ip }

    // Fetch data from multiple sources in parallel
    const [shodanData, virusTotalData, abuseIPDBData, ipInfoData] = await Promise.allSettled([
      fetchShodanData(ip, apiKeys.SHODAN_API_KEY),
      fetchVirusTotalData(ip, apiKeys.VIRUSTOTAL_API_KEY),
      fetchAbuseIPDBData(ip, apiKeys.ABUSEIPDB_API_KEY),
      fetchIPInfoData(ip, apiKeys.IPINFO_API_KEY),
    ])

    // Process results with error handling
    if (shodanData.status === "fulfilled" && shodanData.value) {
      results.shodan = shodanData.value
    } else if (shodanData.status === "rejected") {
      console.warn("Shodan API error:", shodanData.reason)
    }

    if (virusTotalData.status === "fulfilled" && virusTotalData.value) {
      results.virusTotal = virusTotalData.value
    } else if (virusTotalData.status === "rejected") {
      console.warn("VirusTotal API error:", virusTotalData.reason)
    }

    if (abuseIPDBData.status === "fulfilled" && abuseIPDBData.value) {
      results.abuseIPDB = abuseIPDBData.value
    } else if (abuseIPDBData.status === "rejected") {
      console.warn("AbuseIPDB API error:", abuseIPDBData.reason)
    }

    if (ipInfoData.status === "fulfilled" && ipInfoData.value) {
      results.whois = ipInfoData.value
      results.location = {
        country: ipInfoData.value.country || "Unknown",
        city: ipInfoData.value.city || "Unknown",
        coordinates: {
          latitude: ipInfoData.value.loc?.split(",")[0] || null,
          longitude: ipInfoData.value.loc?.split(",")[1] || null,
        },
      }
    } else {
      console.warn("IPInfo API error:", ipInfoData.status === "rejected" ? ipInfoData.reason : "No data")
      results.location = {
        country: "Unknown",
        city: "Unknown",
        coordinates: { latitude: null, longitude: null },
      }
    }

    // Ensure we have at least some data
    const hasData = results.shodan || results.virusTotal || results.abuseIPDB || results.whois
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
    console.error("IP lookup error:", error)
    
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

async function fetchShodanData(ip: string, apiKey: string | undefined) {
  if (!apiKey) return null

  try {
    const fetchWithTimeout = createFetchWithTimeout(API_TIMEOUTS.SHODAN)
    const response = await fetchWithTimeout(`${API_ENDPOINTS.SHODAN}${ip}?key=${apiKey}`)
    
    if (!response.ok) {
      throw new APIError(`Shodan API error: ${response.status}`, response.status, "shodan")
    }

    const data = await response.json()

    return {
      ports: data.ports || [],
      services:
        data.data?.map((service: any) => ({
          port: service.port,
          transport: service.transport,
          product: service.product,
          banner: service.data,
        })) || [],
      lastScan: data.last_update,
    }
  } catch (error) {
    if (error instanceof APIError) {
      throw error
    }
    throw new APIError("Shodan API request failed", 503, "shodan", error)
  }
}

async function fetchVirusTotalData(ip: string, apiKey: string | undefined) {
  if (!apiKey) return null

  try {
    const fetchWithTimeout = createFetchWithTimeout(API_TIMEOUTS.VIRUSTOTAL)
    const response = await fetchWithTimeout(`${API_ENDPOINTS.VIRUSTOTAL.IP}${ip}`, {
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
    const firstSeen = attributes.first_submission_date || null
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

async function fetchAbuseIPDBData(ip: string, apiKey: string | undefined) {
  if (!apiKey) return null

  try {
    const fetchWithTimeout = createFetchWithTimeout(API_TIMEOUTS.ABUSEIPDB)
    const response = await fetchWithTimeout(`${API_ENDPOINTS.ABUSEIPDB}?ipAddress=${ip}&maxAgeInDays=90&verbose=true`, {
      headers: {
        Key: apiKey,
        Accept: "application/json",
      },
    })

    if (!response.ok) {
      throw new APIError(`AbuseIPDB API error: ${response.status}`, response.status, "abuseipdb")
    }

    const data = await response.json()
    const result = data.data

    return {
      abuseScore: result.abuseConfidenceScore,
      totalReports: result.totalReports,
      distinctUsers: result.numDistinctUsers,
      lastReportedAt: result.lastReportedAt,
      usageType: result.usageType,
      reports:
        result.reports?.slice(0, 5).map((report: any) => ({
          reportedAt: report.reportedAt,
          category: report.categories.join(", "),
          comment: report.comment,
        })) || [],
    }
  } catch (error) {
    if (error instanceof APIError) {
      throw error
    }
    throw new APIError("AbuseIPDB API request failed", 503, "abuseipdb", error)
  }
}

async function fetchIPInfoData(ip: string, apiKey: string | undefined) {
  if (!apiKey) return null

  try {
    const fetchWithTimeout = createFetchWithTimeout(API_TIMEOUTS.IPINFO)
    const response = await fetchWithTimeout(`${API_ENDPOINTS.IPINFO}${ip}/json?token=${apiKey}`)
    
    if (!response.ok) {
      throw new APIError(`IPInfo API error: ${response.status}`, response.status, "ipinfo")
    }

    const data = await response.json()

    return {
      organization: data.org,
      asn: data.asn,
      createdDate: null, // IPInfo doesn't provide this
      updatedDate: null, // IPInfo doesn't provide this
      contactEmail: null, // IPInfo doesn't provide this
      ...data,
    }
  } catch (error) {
    if (error instanceof APIError) {
      throw error
    }
    throw new APIError("IPInfo API request failed", 503, "ipinfo", error)
  }
}

function calculateThreatScore(results: any) {
  let score = 0
  let factors = 0

  // Factor in AbuseIPDB score
  if (results.abuseIPDB?.abuseScore) {
    score += results.abuseIPDB.abuseScore
    factors++
  }

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

  // Add organization info
  if (results.whois?.organization) {
    findings.push(`IP belongs to ${results.whois.organization}`)
  }

  // Add threat level finding
  const threatScore = results.threatScore || 0
  if (threatScore >= 80) {
    findings.push("High threat level detected - immediate investigation recommended")
  } else if (threatScore >= 50) {
    findings.push("Medium threat level detected - monitoring recommended")
  } else if (threatScore >= 20) {
    findings.push("Low threat level detected - no immediate action required")
  } else {
    findings.push("No malicious activity reported in the last 90 days")
  }

  // Add port information
  if (results.shodan?.ports?.length > 0) {
    findings.push(
      `${results.shodan.ports.length} open ports detected including ${results.shodan.ports.slice(0, 3).join(", ")}${results.shodan.ports.length > 3 ? "..." : ""}`,
    )
  }

  // Add abuse reports
  if (results.abuseIPDB?.totalReports > 0) {
    findings.push(
      `Reported ${results.abuseIPDB.totalReports} times for abuse by ${results.abuseIPDB.distinctUsers} distinct users`,
    )
  }

  return findings
}
