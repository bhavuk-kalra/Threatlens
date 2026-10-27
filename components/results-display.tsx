"use client"

import { useEffect, useRef, useState } from "react"
import { Check, Copy } from "lucide-react"
import {
  providerIds,
  SOURCE_DEFINITIONS,
  type LookupResult,
  type ProviderId,
  type SourceResult,
} from "@/lib/contracts"

type ResultsDisplayProps = {
  results: LookupResult
  focusOnMount?: boolean
}

type CoverageStatus = SourceResult["status"] | "not_in_response"

const statusLabels: Record<CoverageStatus, string> = {
  available: "Response received",
  not_found: "No matching record",
  disabled: "Disabled",
  unsupported: "Unsupported for this input",
  rate_limited: "Rate limited",
  timeout: "Timed out",
  error: "Could not complete",
  not_in_response: "Not included in response",
}

function formatDate(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime())
    ? "Unknown time"
    : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date)
}

function sourceStatus(source: SourceResult | undefined): CoverageStatus {
  return source?.status ?? "not_in_response"
}

function sourceHasWarning(source: SourceResult) {
  return source.status === "available" && source.findings.some((finding) => finding.kind === "warning")
}

function sourceHasContext(source: SourceResult) {
  return source.status === "available" && source.findings.some((finding) => finding.kind !== "warning")
}

function SourceDetails({ source }: { source: SourceResult }) {
  return (
    <details className="mt-3 text-sm">
      <summary className="inline-flex min-h-11 cursor-pointer items-center text-sm font-medium text-action underline decoration-border underline-offset-4 outline-none focus-visible:ring-2 focus-visible:ring-action">
        Read source note
      </summary>
      <div className="mt-2 border-l border-border pl-3 text-sm leading-6 text-text-muted">
        <p className="break-words">{source.message || "No source message was provided."}</p>
        <dl className="mt-2 grid gap-x-4 gap-y-1 text-xs sm:grid-cols-[max-content_1fr]">
          <dt>Checked</dt>
          <dd>{formatDate(source.checkedAt)}</dd>
          <dt>Observed</dt>
          <dd>{source.observedAt ? formatDate(source.observedAt) : "Not provided"}</dd>
        </dl>
        {source.link?.startsWith("https://") && (
          <a
            href={source.link}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-2 inline-flex min-h-11 items-center text-sm text-action underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-action"
          >
            Open source record
          </a>
        )}
      </div>
    </details>
  )
}

export function ResultsDisplay({ results, focusOnMount = false }: ResultsDisplayProps) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle")
  const headingRef = useRef<HTMLHeadingElement>(null)

  useEffect(() => {
    if (!focusOnMount) return
    const heading = headingRef.current
    if (!heading) return

    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches
    heading.focus({ preventScroll: true })
    heading.scrollIntoView({ behavior: prefersReducedMotion ? "auto" : "smooth", block: "start" })
  }, [focusOnMount])

  const sourceMap = new Map<ProviderId, SourceResult>(results.sources.map((source) => [source.id, source]))
  const warningNotes = results.sources.flatMap((source) =>
    source.status === "available"
      ? source.findings.flatMap((finding, index) => finding.kind === "warning" ? [{ source, finding, index }] : [])
      : [],
  )
  const contextNotes = results.sources.flatMap((source) =>
    source.status === "available"
      ? source.findings.flatMap((finding, index) => finding.kind !== "warning" ? [{ source, finding, index }] : [])
      : [],
  )
  const warningSourceCount = new Set(warningNotes.map(({ source }) => source.id)).size
  const hasContext = contextNotes.length > 0
  const allNoMatch = results.sources.length > 0 && results.sources.every((source) => source.status === "not_found")

  const headline = warningNotes.length > 0
      ? `Warning signals reported by ${warningSourceCount} ${warningSourceCount === 1 ? "source" : "sources"}`
      : hasContext
        ? "Context returned"
        : allNoMatch
          ? "No matching records"
          : "Insufficient evidence"

  const description = warningNotes.length > 0
      ? "These are provider-reported signals, not an independently verified verdict. Sources can disagree."
    : hasContext
      ? "The returned information provides context. Context alone does not establish safety."
      : allNoMatch
        ? "The returned sources reported no matching records. This does not establish safety or absence of activity."
        : "The available response does not provide enough evidence to assess this indicator. Missing or unavailable sources do not imply safety."

  const copyIndicator = async () => {
    try {
      await navigator.clipboard.writeText(results.value)
      setCopyState("copied")
      window.setTimeout(() => setCopyState("idle"), 1800)
    } catch {
      setCopyState("failed")
    }
  }

  const availableCount = [...sourceMap.values()].filter((source) => source.status === "available").length
  const noMatchCount = [...sourceMap.values()].filter((source) => source.status === "not_found").length
  const otherStatusCount = sourceMap.size - availableCount - noMatchCount
  const notIncludedCount = providerIds.length - sourceMap.size
  let noteNumber = 0

  return (
    <article aria-labelledby="lookup-results-heading" className="min-w-0 space-y-8 text-text">
      <header className="border-b border-border pb-7">
        <div className="flex min-w-0 flex-wrap items-start gap-x-3 gap-y-2 font-mono text-xs text-text-muted">
          <span className="shrink-0 uppercase">{results.type}</span>
          <span aria-hidden="true" className="shrink-0">·</span>
          <span className="min-w-0 flex-1 break-all">{results.value}</span>
          <button
            type="button"
            onClick={copyIndicator}
            aria-label={`Copy ${results.type} indicator`}
            className="inline-flex min-h-11 shrink-0 items-center gap-2 border border-border bg-surface px-3 font-sans text-sm font-medium text-text transition-colors motion-reduce:transition-none hover:bg-surface-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-action"
          >
            {copyState === "copied" ? <Check aria-hidden="true" className="h-4 w-4" /> : <Copy aria-hidden="true" className="h-4 w-4" />}
            <span>{copyState === "copied" ? "Copied" : copyState === "failed" ? "Copy failed" : "Copy"}</span>
          </button>
        </div>
        <div className="mt-5 min-w-0">
          <h1
            id="lookup-results-heading"
            ref={headingRef}
            tabIndex={-1}
            className="scroll-mt-36 min-w-0 text-[28px] font-medium leading-tight tracking-tight text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-action sm:text-4xl"
          >
            {headline}
          </h1>
        </div>
        <p className="mt-3 max-w-3xl text-sm leading-6 text-text-muted">{description}</p>
        <p className="sr-only" aria-live="polite">{copyState === "copied" ? "Indicator copied" : copyState === "failed" ? "Could not copy indicator" : ""}</p>
      </header>

      {warningNotes.length > 0 || contextNotes.length > 0 ? (
        <section aria-labelledby="evidence-notes-heading">
          <h2 id="evidence-notes-heading" className="mb-2 text-lg font-semibold text-text">
            {warningNotes.length > 0 ? "Evidence notes" : "Context notes"}
          </h2>
          <ol className="divide-y divide-border border-t border-border">
            {[...warningNotes, ...contextNotes].map(({ source, finding, index }) => {
              noteNumber += 1
              const isWarning = finding.kind === "warning"
              return (
                <li key={`${source.id}-${index}-${finding.kind}`} className="grid min-w-0 gap-x-6 py-5 sm:grid-cols-[7.2rem_minmax(0,1fr)]">
                  <div className="mb-1 flex items-center gap-2 text-xs text-text-muted sm:mb-0 sm:block">
                    <span className="font-mono">{String(noteNumber).padStart(2, "0")}</span>
                    <span className="break-words sm:mt-2 sm:block">{SOURCE_DEFINITIONS[source.id].name}</span>
                  </div>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                      <h3 className="break-words text-base font-semibold leading-6 text-text">{finding.label}</h3>
                      <span className={`text-xs font-medium ${isWarning ? "text-warning" : "text-text-muted"}`}>
                        {isWarning ? "Warning signal" : finding.kind === "context" ? "Context" : "Result"}
                      </span>
                    </div>
                    <p className="mt-2 break-words [overflow-wrap:anywhere] whitespace-pre-wrap text-sm leading-6 text-text">
                      {finding.value.length > 0 ? finding.value : <span className="italic text-text-muted">No additional value supplied.</span>}
                    </p>
                    <SourceDetails source={source} />
                  </div>
                </li>
              )
            })}
          </ol>
        </section>
      ) : (
        <p className="border-y border-border py-5 text-sm leading-6 text-text-muted">
          No available findings were returned. Review source coverage for no-match, unsupported, or unavailable responses.
        </p>
      )}

      <details className="group border-y border-border">
        <summary className="flex min-h-12 cursor-pointer list-none flex-wrap items-center justify-between gap-x-4 gap-y-1 py-3 text-sm font-semibold text-text outline-none focus-visible:ring-2 focus-visible:ring-action [&::-webkit-details-marker]:hidden">
          <span>Source coverage and gaps</span>
          <span className="basis-full text-xs font-normal text-text-muted">
            {availableCount} available · {noMatchCount} no match · {otherStatusCount} other states · {notIncludedCount} not included
          </span>
          <span className="text-xs font-normal text-action group-open:hidden">Show all 10 sources</span>
          <span className="hidden text-xs font-normal text-action group-open:inline">Hide source coverage</span>
        </summary>
        <div className="border-t border-border py-3">
          <p className="mb-2 text-xs leading-5 text-text-muted">Provider states are distinct, and correlated sources are not independent votes.</p>
          <ul className="divide-y divide-border">
            {providerIds.map((id) => {
              const source = sourceMap.get(id)
              const status = sourceStatus(source)
              const wasShownInNotes = source ? sourceHasWarning(source) || sourceHasContext(source) : false
              return (
                <li key={id} className="py-3 first:pt-2 last:pb-2">
                  <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
                    <h3 className="text-sm font-medium text-text">{SOURCE_DEFINITIONS[id].name}</h3>
                    <span className={`text-xs ${status === "error" || status === "timeout" || status === "rate_limited" ? "text-error" : "text-text-muted"}`}>
                      {statusLabels[status]}
                    </span>
                  </div>
                  {source && !wasShownInNotes ? <SourceDetails source={source} /> : !source ? (
                    <p className="mt-1 text-xs text-text-muted">Not included in response.</p>
                  ) : null}
                </li>
              )
            })}
          </ul>
        </div>
      </details>
    </article>
  )
}
