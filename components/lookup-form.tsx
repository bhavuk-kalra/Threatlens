"use client"

import type React from "react"

import { useEffect, useState } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Search, Loader2, AlertTriangle } from "lucide-react"
import { ResultsDisplay } from "@/components/results-display"
import { lookupIP, lookupDomain, lookupHash, getErrorMessage, LookupError } from "@/lib/lookup-service"
import { toast } from "@/hooks/use-toast"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"

type LookupType = "ip" | "domain" | "hash"
type ApiConfig = {
  shodan: boolean
  virusTotal: boolean
  abuseIPDB: boolean
  ipInfo: boolean
}

export function LookupForm() {
  const [lookupValue, setLookupValue] = useState("")
  const [activeTab, setActiveTab] = useState<LookupType>("ip")
  const [isLoading, setIsLoading] = useState(false)
  const [results, setResults] = useState<any>(null)
  const [apiConfig, setApiConfig] = useState<ApiConfig | null>(null)
  const [isCheckingConfig, setIsCheckingConfig] = useState(true)

  useEffect(() => {
    // Check which API keys are configured
    async function checkApiConfig() {
      try {
        const response = await fetch("/api/config")
        if (response.ok) {
          const config = await response.json()
          setApiConfig(config)
        }
      } catch (error) {
        console.error("Failed to check API configuration:", error)
      } finally {
        setIsCheckingConfig(false)
      }
    }

    checkApiConfig()
  }, [])

  const handleTabChange = (value: string) => {
    setActiveTab(value as LookupType)
    setLookupValue("")
    setResults(null)
  }

  const validateInput = () => {
    if (!lookupValue.trim()) {
      toast({
        title: "Input required",
        description: "Please enter a value to lookup",
        variant: "destructive",
      })
      return false
    }

    // Enhanced validation patterns
    const patterns = {
      ip: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
      domain: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/,
      hash: /^[a-fA-F0-9]+$/,
    }

    if (!patterns[activeTab].test(lookupValue)) {
      let errorMessage = `Please enter a valid ${activeTab}`
      
      if (activeTab === "ip") {
        errorMessage = "Please enter a valid IP address (e.g., 8.8.8.8)"
      } else if (activeTab === "domain") {
        errorMessage = "Please enter a valid domain name (e.g., example.com)"
      } else if (activeTab === "hash") {
        errorMessage = "Please enter a valid hash (MD5, SHA-1, SHA-256, or SHA-512)"
      }

      toast({
        title: "Invalid format",
        description: errorMessage,
        variant: "destructive",
      })
      return false
    }

    // Additional validation for hash length
    if (activeTab === "hash") {
      const length = lookupValue.length
      if (![32, 40, 64, 128].includes(length)) {
        toast({
          title: "Invalid hash length",
          description: "Hash must be MD5 (32), SHA-1 (40), SHA-256 (64), or SHA-512 (128) characters",
          variant: "destructive",
        })
        return false
      }
    }

    return true
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!validateInput()) return

    setIsLoading(true)
    setResults(null)

    try {
      let result

      switch (activeTab) {
        case "ip":
          result = await lookupIP(lookupValue)
          break
        case "domain":
          result = await lookupDomain(lookupValue)
          break
        case "hash":
          result = await lookupHash(lookupValue)
          break
      }

      setResults(result)
    } catch (error) {
      console.error("Lookup error:", error)
      const errorMessage = getErrorMessage(error)
      
      toast({
        title: "Lookup failed",
        description: errorMessage,
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  // Show missing API key warnings
  const renderApiWarnings = () => {
    if (!apiConfig || isCheckingConfig) return null

    const missingApis = []

    if (!apiConfig.shodan) missingApis.push("Shodan")
    if (!apiConfig.virusTotal) missingApis.push("VirusTotal")
    if (!apiConfig.abuseIPDB) missingApis.push("AbuseIPDB")
    if (!apiConfig.ipInfo) missingApis.push("IPInfo")

    if (missingApis.length === 0) return null

    return (
      <Alert variant="warning" className="mb-4">
        <AlertTriangle className="h-4 w-4 non-selectable" />
        <AlertTitle>Missing API Keys</AlertTitle>
        <AlertDescription>
          <p>
            The following API keys are not configured: {missingApis.join(", ")}. Mock data will be used for
            demonstration.
          </p>
          <p className="mt-2">To use real data, add your API keys in the environment variables.</p>
        </AlertDescription>
      </Alert>
    )
  }

  return (
    <div className="space-y-8">
      {renderApiWarnings()}

      <Card className="p-6 bg-black border-none">
        <Tabs defaultValue="ip" value={activeTab} onValueChange={handleTabChange}>
          <TabsList className="grid grid-cols-3 mb-6 tabs-list">
            <TabsTrigger value="ip" className="tabs-trigger non-selectable">
              IP Address
            </TabsTrigger>
            <TabsTrigger value="domain" className="tabs-trigger non-selectable">
              Domain
            </TabsTrigger>
            <TabsTrigger value="hash" className="tabs-trigger non-selectable">
              File Hash
            </TabsTrigger>
          </TabsList>

          <form onSubmit={handleSubmit} className="space-y-4">
            <TabsContent value="ip">
              <div className="space-y-2">
                <h3 className="text-lg font-medium">IP Address Lookup</h3>
                <p className="text-sm text-gray-500">
                  Enter an IP address to get information about open ports, geolocation, and reputation.
                </p>
                <Input
                  placeholder="e.g. 8.8.8.8"
                  value={lookupValue}
                  onChange={(e) => setLookupValue(e.target.value)}
                  className="bg-gray-900"
                />
              </div>
            </TabsContent>

            <TabsContent value="domain">
              <div className="space-y-2">
                <h3 className="text-lg font-medium">Domain Lookup</h3>
                <p className="text-sm text-gray-500">
                  Enter a domain to get WHOIS information, malware detection stats, and more.
                </p>
                <Input
                  placeholder="e.g. example.com"
                  value={lookupValue}
                  onChange={(e) => setLookupValue(e.target.value)}
                  className="bg-gray-900"
                />
              </div>
            </TabsContent>

            <TabsContent value="hash">
              <div className="space-y-2">
                <h3 className="text-lg font-medium">File Hash Lookup</h3>
                <p className="text-sm text-gray-500">
                  Enter an MD5, SHA-1, or SHA-256 hash to check for malware detection.
                </p>
                <Input
                  placeholder="e.g. 44d88612fea8a8f36de82e1278abb02f"
                  value={lookupValue}
                  onChange={(e) => setLookupValue(e.target.value)}
                  className="bg-gray-900"
                />
              </div>
            </TabsContent>

            <Button type="submit" className="w-full button non-selectable" disabled={isLoading}>
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin non-selectable" />
                  Searching...
                </>
              ) : (
                <>
                  <Search className="mr-2 h-4 w-4 non-selectable" />
                  Lookup
                </>
              )}
            </Button>
          </form>
        </Tabs>
      </Card>

      {results && <ResultsDisplay results={results} type={activeTab} />}
    </div>
  )
}
