import { NextResponse } from "next/server"
import { areApiKeysConfigured, areRequiredApiKeysConfigured } from "@/lib/api-config"

export async function GET() {
  try {
    // Return which API keys are configured
    const configuredKeys = areApiKeysConfigured()
    const hasRequiredKeys = areRequiredApiKeysConfigured()
    
    return NextResponse.json({
      ...configuredKeys,
      hasRequiredKeys,
    })
  } catch (error) {
    console.error("Config API error:", error)
    return NextResponse.json(
      { error: "Failed to check API configuration" },
      { status: 500 }
    )
  }
}
