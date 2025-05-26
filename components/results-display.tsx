"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { AlertTriangle, CheckCircle, Globe, Shield, Activity, Download } from "lucide-react"
import { Button } from "@/components/ui/button"

type ResultsDisplayProps = {
  results: any
  type: "ip" | "domain" | "hash"
}

export function ResultsDisplay({ results, type }: ResultsDisplayProps) {
  const [activeSource, setActiveSource] = useState("summary")

  // Dispatch custom event when results are loaded
  useEffect(() => {
    // Dispatch a custom event that results have loaded
    const event = new CustomEvent("resultsLoaded")
    window.dispatchEvent(event)

    // Apply non-selectable attributes to interactive elements
    const applyNonSelectable = () => {
      const interactiveElements = document.querySelectorAll(
        ".results-page button, .results-page [role='button'], .results-page .tabs-list, " +
          ".results-page .tabs-trigger, .results-page .button, .results-page .badge",
      )

      interactiveElements.forEach((el) => {
        el.setAttribute("unselectable", "on")
        el.classList.add("non-selectable")
      })
    }

    // Run immediately and after a short delay to ensure DOM is updated
    applyNonSelectable()
    setTimeout(applyNonSelectable, 100)
  }, [results])

  if (!results) return null

  const getSeverityColor = (score = 0) => {
    if (score >= 80) return "bg-red-500"
    if (score >= 50) return "bg-orange-500"
    if (score >= 20) return "bg-yellow-500"
    return "bg-green-500"
  }

  const formatDate = (dateString: string | number | null | undefined) => {
    if (!dateString) return "Unknown"

    // If it's a number (Unix timestamp), convert to milliseconds if needed
    if (typeof dateString === "number") {
      // Check if it's a Unix timestamp in seconds (VirusTotal format)
      // Unix timestamps in seconds are typically 10 digits for recent dates
      if (dateString < 10000000000) {
        dateString = dateString * 1000 // Convert to milliseconds
      }
    }

    const date = new Date(dateString)

    // Check if date is valid and not the Unix epoch (1970-01-01)
    if (isNaN(date.getTime()) || date.getFullYear() === 1970) {
      return "Unknown"
    }

    return date.toLocaleString()
  }

  const renderSummary = () => {
    const threatScore = results.threatScore || 0

    return (
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span>Threat Summary</span>
            <Badge className={`${getSeverityColor(threatScore)} non-selectable`}>Score: {threatScore}/100</Badge>
          </CardTitle>
          <CardDescription>
            {type === "ip" && `IP Address: ${results.ip}`}
            {type === "domain" && `Domain: ${results.domain}`}
            {type === "hash" && `File Hash: ${results.hash}`}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-800 p-4 rounded-lg">
              <div className="flex items-center space-x-2 mb-2">
                <Globe className="h-5 w-5 text-blue-400 non-selectable" />
                <h3 className="font-medium">Location</h3>
              </div>
              <p className="text-slate-300">
                {results.location?.country || "Unknown"}
                {results.location?.city ? `, ${results.location.city}` : ""}
              </p>
              {results.location?.coordinates && (
                <p className="text-sm text-slate-400">
                  Lat: {results.location.coordinates.latitude}, Long: {results.location.coordinates.longitude}
                </p>
              )}
            </div>

            <div className="bg-slate-800 p-4 rounded-lg">
              <div className="flex items-center space-x-2 mb-2">
                <Shield className="h-5 w-5 text-blue-400 non-selectable" />
                <h3 className="font-medium">Risk Assessment</h3>
              </div>
              <div className="flex items-center space-x-2">
                {threatScore >= 50 ? (
                  <AlertTriangle className="h-5 w-5 text-red-500 non-selectable" />
                ) : (
                  <CheckCircle className="h-5 w-5 text-green-500 non-selectable" />
                )}
                <p className="text-slate-300">
                  {threatScore >= 80
                    ? "High Risk"
                    : threatScore >= 50
                      ? "Medium Risk"
                      : threatScore >= 20
                        ? "Low Risk"
                        : "Safe"}
                </p>
              </div>
              <p className="text-sm text-slate-400 mt-1">
                {threatScore >= 50
                  ? "This indicator has been associated with malicious activity."
                  : "No significant threats detected."}
              </p>
            </div>
          </div>

          <div className="bg-slate-800 p-4 rounded-lg">
            <div className="flex items-center space-x-2 mb-2">
              <Activity className="h-5 w-5 text-blue-400 non-selectable" />
              <h3 className="font-medium">Key Findings</h3>
            </div>
            <ul className="space-y-2 text-slate-300">
              {results.keyFindings?.map((finding: string, index: number) => (
                <li key={index} className="flex items-start space-x-2">
                  <span className="text-blue-400 non-selectable">•</span>
                  <span>{finding}</span>
                </li>
              ))}
              {(!results.keyFindings || results.keyFindings.length === 0) && (
                <li className="text-slate-400">No significant findings</li>
              )}
            </ul>
          </div>
        </CardContent>
      </Card>
    )
  }

  const renderShodan = () => {
    if (!results.shodan) {
      return (
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle>Shodan</CardTitle>
            <CardDescription>No Shodan data available</CardDescription>
          </CardHeader>
        </Card>
      )
    }

    return (
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle>Shodan Intelligence</CardTitle>
          <CardDescription>Open ports, services, and banner information</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="bg-slate-800 p-4 rounded-lg">
            <h3 className="font-medium mb-2">Open Ports</h3>
            <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-6 gap-2">
              {results.shodan.ports?.map((port: number) => (
                <Badge key={port} variant="outline" className="justify-center non-selectable">
                  {port}
                </Badge>
              ))}
              {(!results.shodan.ports || results.shodan.ports.length === 0) && (
                <p className="text-slate-400 col-span-full">No open ports detected</p>
              )}
            </div>
          </div>

          <div className="bg-slate-800 p-4 rounded-lg">
            <h3 className="font-medium mb-2">Services</h3>
            <div className="space-y-3">
              {results.shodan.services?.map((service: any, index: number) => (
                <div key={index} className="border-b border-slate-700 pb-3 last:border-0 last:pb-0">
                  <div className="flex justify-between">
                    <span className="font-medium text-blue-400">
                      {service.port}/{service.transport || "tcp"}
                    </span>
                    <Badge variant="outline" className="non-selectable">
                      {service.product || "Unknown"}
                    </Badge>
                  </div>
                  <p className="text-sm text-slate-400 mt-1">{service.banner || "No banner information"}</p>
                </div>
              ))}
              {(!results.shodan.services || results.shodan.services.length === 0) && (
                <p className="text-slate-400">No services detected</p>
              )}
            </div>
          </div>

          {results.shodan.lastScan && (
            <p className="text-sm text-slate-400">Last scanned: {formatDate(results.shodan.lastScan)}</p>
          )}
        </CardContent>
      </Card>
    )
  }

  const renderVirusTotal = () => {
    if (!results.virusTotal) {
      return (
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle>VirusTotal</CardTitle>
            <CardDescription>No VirusTotal data available</CardDescription>
          </CardHeader>
        </Card>
      )
    }

    const { detectionRatio, firstSeen, lastSeen, categories } = results.virusTotal
    const [detected, total] = detectionRatio ? detectionRatio.split("/").map(Number) : [0, 0]
    const detectionPercentage = total > 0 ? (detected / total) * 100 : 0

    return (
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle>VirusTotal Analysis</CardTitle>
          <CardDescription>Malware detection statistics and categorization</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="bg-slate-800 p-4 rounded-lg">
            <h3 className="font-medium mb-2">Detection Summary</h3>
            <div className="flex items-center space-x-4">
              <div className="w-16 h-16 rounded-full flex items-center justify-center border-4 border-slate-700 non-selectable">
                <span
                  className={`text-lg font-bold non-selectable ${detectionPercentage >= 50 ? "text-red-500" : detectionPercentage > 0 ? "text-yellow-500" : "text-green-500"}`}
                >
                  {Math.round(detectionPercentage)}%
                </span>
              </div>
              <div>
                <p className="text-slate-300">{detectionRatio || "0/0"} engines detected this as malicious</p>
                <p className="text-sm text-slate-400">
                  {detectionPercentage >= 50
                    ? "High detection rate"
                    : detectionPercentage > 0
                      ? "Low detection rate"
                      : "No detections"}
                </p>
              </div>
            </div>
          </div>

          {categories && Object.keys(categories).length > 0 && (
            <div className="bg-slate-800 p-4 rounded-lg">
              <h3 className="font-medium mb-2">Categories</h3>
              <div className="flex flex-wrap gap-2">
                {Object.entries(categories).map(([category, count]) => (
                  <Badge key={category} variant="secondary" className="non-selectable">
                    {category}: {count as number}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {firstSeen && (
              <div className="bg-slate-800 p-4 rounded-lg">
                <h3 className="font-medium mb-1">First Seen</h3>
                <p className="text-slate-300">{formatDate(firstSeen)}</p>
              </div>
            )}

            {lastSeen && (
              <div className="bg-slate-800 p-4 rounded-lg">
                <h3 className="font-medium mb-1">Last Seen</h3>
                <p className="text-slate-300">{formatDate(lastSeen)}</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    )
  }

  const renderWhois = () => {
    if (!results.whois) {
      return (
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle>WHOIS/IPInfo</CardTitle>
            <CardDescription>No WHOIS/IPInfo data available</CardDescription>
          </CardHeader>
        </Card>
      )
    }

    return (
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle>WHOIS / IPInfo</CardTitle>
          <CardDescription>Registration and ownership information</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-800 p-4 rounded-lg">
              <h3 className="font-medium mb-2">Ownership</h3>
              <div className="space-y-2">
                {results.whois.organization && (
                  <div>
                    <p className="text-sm text-slate-400">Organization</p>
                    <p className="text-slate-300">{results.whois.organization}</p>
                  </div>
                )}
                {results.whois.registrar && (
                  <div>
                    <p className="text-sm text-slate-400">Registrar</p>
                    <p className="text-slate-300">{results.whois.registrar}</p>
                  </div>
                )}
                {results.whois.asn && (
                  <div>
                    <p className="text-sm text-slate-400">ASN</p>
                    <p className="text-slate-300">{results.whois.asn}</p>
                  </div>
                )}
              </div>
            </div>

            <div className="bg-slate-800 p-4 rounded-lg">
              <h3 className="font-medium mb-2">Registration</h3>
              <div className="space-y-2">
                {results.whois.createdDate && (
                  <div>
                    <p className="text-sm text-slate-400">Created Date</p>
                    <p className="text-slate-300">{formatDate(results.whois.createdDate)}</p>
                  </div>
                )}
                {results.whois.updatedDate && (
                  <div>
                    <p className="text-sm text-slate-400">Updated Date</p>
                    <p className="text-slate-300">{formatDate(results.whois.updatedDate)}</p>
                  </div>
                )}
                {results.whois.expiresDate && (
                  <div>
                    <p className="text-sm text-slate-400">Expires Date</p>
                    <p className="text-slate-300">{formatDate(results.whois.expiresDate)}</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {results.whois.nameServers && results.whois.nameServers.length > 0 && (
            <div className="bg-slate-800 p-4 rounded-lg">
              <h3 className="font-medium mb-2">Name Servers</h3>
              <ul className="space-y-1">
                {results.whois.nameServers.map((ns: string, index: number) => (
                  <li key={index} className="text-slate-300">
                    {ns}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {results.whois.contactEmail && (
            <div className="bg-slate-800 p-4 rounded-lg">
              <h3 className="font-medium mb-2">Contact Information</h3>
              <p className="text-slate-300">{results.whois.contactEmail}</p>
            </div>
          )}
        </CardContent>
      </Card>
    )
  }

  const renderAbuseIPDB = () => {
    if (!results.abuseIPDB) {
      return (
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle>AbuseIPDB</CardTitle>
            <CardDescription>No AbuseIPDB data available</CardDescription>
          </CardHeader>
        </Card>
      )
    }

    return (
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span>AbuseIPDB</span>
            <Badge className={`${getSeverityColor(results.abuseIPDB.abuseScore)} non-selectable`}>
              Score: {results.abuseIPDB.abuseScore}/100
            </Badge>
          </CardTitle>
          <CardDescription>IP reputation and abuse reports</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="bg-slate-800 p-4 rounded-lg">
            <h3 className="font-medium mb-2">Abuse Reports</h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-2xl font-bold text-blue-400">{results.abuseIPDB.totalReports || 0}</p>
                <p className="text-sm text-slate-400">Total Reports</p>
              </div>
              <div>
                <p className="text-2xl font-bold text-blue-400">
                  {results.abuseIPDB.lastReportedAt
                    ? formatDate(results.abuseIPDB.lastReportedAt).split(",")[0]
                    : "Never"}
                </p>
                <p className="text-sm text-slate-400">Last Reported</p>
              </div>
              <div>
                <p className="text-2xl font-bold text-blue-400">{results.abuseIPDB.distinctUsers || 0}</p>
                <p className="text-sm text-slate-400">Distinct Reporters</p>
              </div>
            </div>
          </div>

          {results.abuseIPDB.reports && results.abuseIPDB.reports.length > 0 && (
            <div className="bg-slate-800 p-4 rounded-lg">
              <h3 className="font-medium mb-2">Recent Reports</h3>
              <div className="space-y-3">
                {results.abuseIPDB.reports.map((report: any, index: number) => (
                  <div key={index} className="border-b border-slate-700 pb-3 last:border-0 last:pb-0">
                    <div className="flex justify-between mb-1">
                      <span className="text-slate-300">{formatDate(report.reportedAt)}</span>
                      <Badge variant="outline" className="non-selectable">
                        {report.category}
                      </Badge>
                    </div>
                    <p className="text-sm text-slate-400">{report.comment || "No comment provided"}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {results.abuseIPDB.usageType && (
            <div className="bg-slate-800 p-4 rounded-lg">
              <h3 className="font-medium mb-2">Usage Type</h3>
              <p className="text-slate-300">{results.abuseIPDB.usageType}</p>
            </div>
          )}
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-4 results-page">
      <h2 className="text-2xl font-bold">Results</h2>

      <Tabs value={activeSource} onValueChange={setActiveSource}>
        <TabsList className="grid grid-cols-2 md:grid-cols-5 tabs-list">
          <TabsTrigger value="summary" className="tabs-trigger non-selectable">
            Summary
          </TabsTrigger>
          <TabsTrigger value="shodan" className="tabs-trigger non-selectable">
            Shodan
          </TabsTrigger>
          <TabsTrigger value="virustotal" className="tabs-trigger non-selectable">
            VirusTotal
          </TabsTrigger>
          <TabsTrigger value="whois" className="tabs-trigger non-selectable">
            WHOIS/IPInfo
          </TabsTrigger>
          <TabsTrigger value="abuseipdb" className="tabs-trigger non-selectable">
            AbuseIPDB
          </TabsTrigger>
        </TabsList>

        <div className="mt-4">
          <TabsContent value="summary">{renderSummary()}</TabsContent>

          <TabsContent value="shodan">{renderShodan()}</TabsContent>

          <TabsContent value="virustotal">{renderVirusTotal()}</TabsContent>

          <TabsContent value="whois">{renderWhois()}</TabsContent>

          <TabsContent value="abuseipdb">{renderAbuseIPDB()}</TabsContent>
        </div>
      </Tabs>
    </div>
  )
}
