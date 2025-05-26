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
  hashLookupRequestSchema, 
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

    const validation = validateInput(hashLookupRequestSchema, body)
    if (!validation.success) {
      return NextResponse.json(
        { error: validation.error },
        { status: 400 }
      )
    }

    const { hash } = validation.data
    const apiKeys = getApiKeys()
    const results: any = { hash }

    // Fetch data from VirusTotal
    if (apiKeys.VIRUSTOTAL_API_KEY) {
      try {
        results.virusTotal = await fetchVirusTotalData(hash, apiKeys.VIRUSTOTAL_API_KEY)
      } catch (error) {
        console.warn("VirusTotal API error:", error)
      }
    }

    // Ensure we have at least some data
    if (!results.virusTotal) {
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
    console.error("Hash lookup error:", error)
    
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

async function fetchVirusTotalData(hash: string, apiKey: string | undefined) {
  if (!apiKey) return null

  try {
    const fetchWithTimeout = createFetchWithTimeout(API_TIMEOUTS.VIRUSTOTAL)
    const response = await fetchWithTimeout(`${API_ENDPOINTS.VIRUSTOTAL.FILE}${hash}`, {
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

    // Extract malware categories from detection results
    const malwareCategories: Record<string, number> = {}
    if (attributes.last_analysis_results) {
      Object.entries(attributes.last_analysis_results).forEach(([engine, result]: [string, any]) => {
        if (result.category === "malicious" && result.result) {
          const category = result.result.toLowerCase()
          malwareCategories[category] = (malwareCategories[category] || 0) + 1
        }
      })
    }

    return {
      detectionRatio: `${attributes.last_analysis_stats.malicious}/${Object.keys(attributes.last_analysis_results).length}`,
      firstSeen: firstSeen,
      lastSeen: lastSeen,
      categories: malwareCategories,
      fileSize: attributes.size || null,
      fileType: attributes.type_description || null,
      md5: attributes.md5 || null,
      sha1: attributes.sha1 || null,
      sha256: attributes.sha256 || null,
      names: attributes.names || [],
    }
  } catch (error) {
    if (error instanceof APIError) {
      throw error
    }
    throw new APIError("VirusTotal API request failed", 503, "virustotal", error)
  }
}

function calculateThreatScore(results: any) {
  if (!results.virusTotal?.detectionRatio) return 0

  const [detected, total] = results.virusTotal.detectionRatio.split("/").map(Number)
  return total > 0 ? Math.round((detected / total) * 100) : 0
}

function generateKeyFindings(results: any) {
  const findings = []

  // Add detection info
  if (results.virusTotal?.detectionRatio) {
    const [detected, total] = results.virusTotal.detectionRatio.split("/").map(Number)

    if (detected > 0) {
      findings.push(`Detected as malware by ${detected}/${total} antivirus engines`)

      // Add threat level assessment
      const detectionRate = (detected / total) * 100
      if (detectionRate >= 80) {
        findings.push("High confidence malware detection - immediate action required")
      } else if (detectionRate >= 50) {
        findings.push("Medium confidence malware detection - investigation recommended")
      } else if (detectionRate >= 20) {
        findings.push("Low confidence malware detection - proceed with caution")
      } else {
        findings.push("Minimal malware detection - likely false positives")
      }

      // Add first seen info
      if (results.virusTotal.firstSeen) {
        try {
          const firstSeenDate = new Date(results.virusTotal.firstSeen * 1000) // Convert Unix timestamp to milliseconds
          if (!isNaN(firstSeenDate.getTime()) && firstSeenDate.getFullYear() > 1970) {
            const daysAgo = Math.floor((Date.now() - firstSeenDate.getTime()) / (1000 * 60 * 60 * 24))
            if (daysAgo >= 0) {
              findings.push(`First seen in the wild ${daysAgo} ${daysAgo === 1 ? "day" : "days"} ago`)
            }
          }
        } catch (error) {
          console.warn("Error calculating first seen date:", error)
        }
      }

      // Add malware categories
      const categories = results.virusTotal.categories
      if (categories && Object.keys(categories).length > 0) {
        const topCategories = Object.entries(categories)
          .sort((a: any, b: any) => b[1] - a[1])
          .slice(0, 3)
          .map((entry: any) => entry[0])

        if (topCategories.length > 0) {
          findings.push(`Primary threat types: ${topCategories.join(", ")}`)
        }
      }
    } else {
      findings.push("No detections by any antivirus engines")
      findings.push("File appears to be legitimate")
    }

    // Add file information
    if (results.virusTotal.fileType) {
      findings.push(`File type: ${results.virusTotal.fileType}`)
    }

    if (results.virusTotal.fileSize) {
      const sizeInKB = Math.round(results.virusTotal.fileSize / 1024)
      const sizeInMB = Math.round(results.virusTotal.fileSize / (1024 * 1024))
      
      if (sizeInMB > 0) {
        findings.push(`File size: ${sizeInMB} MB`)
      } else {
        findings.push(`File size: ${sizeInKB} KB`)
      }
    }

    // Add common file names if available
    if (results.virusTotal.names && results.virusTotal.names.length > 0) {
      const commonNames = results.virusTotal.names.slice(0, 3)
      findings.push(`Common file names: ${commonNames.join(", ")}`)
    }
  } else {
    findings.push("No VirusTotal data available")
  }

  return findings
}
