"use client";

import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { ArrowUpRight, Loader2, Search, X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { ResultsDisplay } from "@/components/results-display";
import {
  SOURCE_DEFINITIONS,
  lookupRequestSchema,
  providerIds,
  type LookupResult,
  type LookupType,
  type ProviderGroup,
  type ProviderId,
} from "@/lib/contracts";
import { lookup, LookupError } from "@/lib/lookup-service";

const groups: { id: ProviderGroup; title: string }[] = [
  { id: "reputation", title: "Reputation" },
  { id: "malware", title: "Malware intelligence" },
  { id: "infrastructure", title: "Infrastructure" },
  { id: "community", title: "Community intelligence" },
];

const defaultSources: Record<LookupType, ProviderId[]> = {
  ip: ["virustotal", "abuseipdb", "ipinfo"],
  domain: ["virustotal", "urlhaus", "urlscan"],
  hash: ["virustotal", "threatfox", "malwarebazaar"],
};

const typeLabels: Record<LookupType, string> = { ip: "IP address", domain: "Domain", hash: "File hash" };

function detectType(rawValue: string): LookupType {
  const value = rawValue.trim();
  if (/^(?:[a-f\d]{32}|[a-f\d]{40}|[a-f\d]{64})$/i.test(value)) return "hash";
  // Keep malformed numeric/IPv6-looking input on the IP path so it cannot be
  // accepted as a domain after the user mistypes an address.
  if (/^[\d.]+$/.test(value) || value.includes(":")) return "ip";
  return "domain";
}

export function LookupForm() {
  const [type, setType] = useState<LookupType>("ip");
  const [typeOverride, setTypeOverride] = useState<"auto" | LookupType>("auto");
  const [value, setValue] = useState("");
  const [selectedSources, setSelectedSources] = useState<ProviderId[]>(defaultSources.ip);
  const [liveEnabled, setLiveEnabled] = useState(false);
  const [isCheckingConfig, setIsCheckingConfig] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [inputInvalid, setInputInvalid] = useState(false);
  const [results, setResults] = useState<LookupResult | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const returnFocus = useRef(false);
  const controller = useRef<AbortController | null>(null);
  const requestIdentity = useRef(0);

  useEffect(() => {
    const configController = new AbortController();
    void fetch("/api/config", { signal: configController.signal })
      .then(async (response) => {
        if (!response.ok) return false;
        const payload: unknown = await response.json();
        return Boolean(payload && typeof payload === "object" && "liveEnabled" in payload && payload.liveEnabled === true);
      })
      .then((enabled) => setLiveEnabled(enabled))
      .catch(() => {
        if (!configController.signal.aborted) setLiveEnabled(false);
      })
      .finally(() => {
        if (!configController.signal.aborted) setIsCheckingConfig(false);
      });
    return () => configController.abort();
  }, []);

  useEffect(() => () => {
    requestIdentity.current += 1;
    controller.current?.abort();
  }, []);

  useEffect(() => {
    if (!results && returnFocus.current) {
      returnFocus.current = false;
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [results]);

  const cancelPending = useCallback((showCancelled = false) => {
    requestIdentity.current += 1;
    controller.current?.abort();
    controller.current = null;
    setIsLoading(false);
    if (showCancelled) setError("Lookup cancelled.");
  }, []);

  const invalidateView = (cancelled = false) => {
    cancelPending(cancelled);
    setResults(null);
    setError(null);
    setInputInvalid(false);
  };

  const changeValue = (nextValue: string) => {
    invalidateView();
    setValue(nextValue);
    if (typeOverride === "auto") {
      const detected = detectType(nextValue);
      if (detected !== type) {
        setType(detected);
        setSelectedSources(defaultSources[detected]);
      }
    }
  };

  const toggleSource = (sourceId: ProviderId, checked: boolean) => {
    invalidateView();
    setSelectedSources((current) => checked
      ? current.includes(sourceId) ? current : [...current, sourceId]
      : current.filter((id) => id !== sourceId));
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    invalidateView();

    if (!liveEnabled) {
      setError("Live lookup is not available in this environment.");
      return;
    }

    const parsed = lookupRequestSchema.safeParse({ type, value, sourceIds: selectedSources });
    if (!parsed.success) {
      setError(parsed.error.issues[0]?.message ?? "Enter a valid indicator and select at least one source.");
      setInputInvalid(parsed.error.issues.some((issue) => issue.path.includes("value")));
      return;
    }

    const activeController = new AbortController();
    const identity = ++requestIdentity.current;
    controller.current = activeController;
    setIsLoading(true);
    try {
      const result = await lookup(parsed.data, activeController.signal);
      if (requestIdentity.current === identity) setResults(result);
    } catch (caught) {
      if (requestIdentity.current !== identity || activeController.signal.aborted) return;
      setError(caught instanceof LookupError ? caught.message : "The lookup could not be completed. Try again.");
    } finally {
      if (requestIdentity.current === identity) {
        controller.current = null;
        setIsLoading(false);
      }
    }
  };

  const returnToSearch = (focus = true) => {
    cancelPending();
    returnFocus.current = focus;
    setResults(null);
    setError(null);
  };

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.isComposing || event.keyCode === 229 || !(event.metaKey || event.ctrlKey) || event.altKey || event.shiftKey || event.key.toLowerCase() !== "k") return;
      event.preventDefault();
      if (results) returnToSearch(true);
      else inputRef.current?.focus();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [results]);

  const compatibleSources = providerIds.filter((id) => SOURCE_DEFINITIONS[id].supportedTypes.some((supportedType) => supportedType === type));
  const inputLabel = "IP address, domain, or file hash";
  const placeholder = type === "ip" ? "Enter IPv4 address" : type === "domain" ? "Enter domain name" : "Enter MD5, SHA-1, or SHA-256 hash";

  if (results) {
    return (
      <div className="space-y-5 text-left">
        <nav aria-label="Lookup navigation" className="flex min-h-11 items-center justify-between gap-4 border-b border-border pb-3">
          <button type="button" onClick={() => returnToSearch(true)} className="min-h-11 rounded-sm pr-2 text-sm font-medium text-action underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-action">
            New lookup
          </button>
          <span className="text-xs font-medium uppercase tracking-[0.12em] text-text-muted">Live lookup</span>
        </nav>
        <ResultsDisplay key={`${results.type}:${results.value}`} results={results} focusOnMount />
      </div>
    );
  }

  return (
    <div className="min-w-0 space-y-12 text-left sm:space-y-14">
      <section aria-labelledby="lookup-hero-heading" className="min-w-0">
        <div className="grid min-w-0 gap-5 md:grid-cols-[minmax(0,1.4fr)_minmax(210px,0.6fr)] md:items-end md:gap-10">
          <div className="min-w-0">
            <p className="mb-4 text-xs font-semibold uppercase tracking-[0.13em] text-text-muted">A clearer view of the evidence</p>
            <h1 id="lookup-hero-heading" className="max-w-[760px] text-[clamp(2.625rem,6vw,4.25rem)] font-medium leading-[1.05] tracking-[-0.045em] text-text">
              Every indicator<br className="hidden sm:block" /> has a story.
            </h1>
          </div>
          <p className="max-w-[260px] text-base leading-7 text-text-muted md:pb-1">Trace the signals.<br />Compare the sources.<br />Make your own call.</p>
        </div>

        <form onSubmit={handleSubmit} noValidate className="mt-9">
          <div className="grid min-w-0 grid-cols-[20px_minmax(0,1fr)] items-center border border-text bg-surface p-1 sm:flex sm:items-stretch">
            <Search aria-hidden="true" className="ml-3 h-4 w-4 shrink-0 self-center text-text-muted" />
            <label className="sr-only" htmlFor="lookup-value">{inputLabel}</label>
            <Input
              ref={inputRef}
              id="lookup-value"
              autoComplete="off"
              spellCheck={false}
              inputMode="text"
              value={value}
              onChange={(event) => changeValue(event.target.value)}
              placeholder={placeholder}
              aria-describedby="lookup-hint"
              aria-invalid={inputInvalid}
              className="col-start-2 h-12 min-w-0 self-center flex-1 border-0 bg-transparent px-3 font-mono text-base text-text placeholder:text-text-muted focus-visible:ring-0 sm:h-[54px]"
            />
            <button type="submit" disabled={isLoading || !liveEnabled || selectedSources.length === 0} className="col-span-2 inline-flex min-h-12 items-center justify-center gap-2 self-stretch rounded-[3px] bg-action px-5 py-3 text-sm font-semibold text-action-foreground transition-colors duration-150 hover:brightness-95 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-action focus-visible:ring-offset-2 focus-visible:ring-offset-surface disabled:cursor-not-allowed disabled:opacity-60 sm:col-span-1 sm:min-h-[54px] sm:min-w-[142px]">
              {isLoading ? <><Loader2 aria-hidden="true" className="h-4 w-4 animate-spin motion-reduce:animate-none" /> Investigating…</> : <><span>Investigate</span><ArrowUpRight aria-hidden="true" className="h-4 w-4" /></>}
            </button>
          </div>
          <div className="mt-3 flex min-w-0 flex-col gap-2 text-sm sm:flex-row sm:items-center sm:justify-between">
            <p id="lookup-hint" className="text-text-muted">
              Your indicator is sent to the selected providers when you investigate.
            </p>
            <p className="text-xs text-text-muted">{isLoading ? "Checking selected sources…" : isCheckingConfig ? "Checking lookup availability…" : liveEnabled ? "Live lookups are available." : "Live lookup is unavailable."}</p>
          </div>
          {!isCheckingConfig && !liveEnabled && <p role="status" className="mt-3 text-sm text-text-muted">Live lookup is unavailable because this environment is not configured for provider requests.</p>}
          {error && <p role="alert" className="mt-3 border-l-2 border-error pl-3 text-sm leading-6 text-error">{error}</p>}
          {isLoading && <button type="button" onClick={() => cancelPending(true)} className="mt-3 inline-flex min-h-11 items-center gap-2 rounded-sm border border-border px-3 text-sm font-medium text-text hover:bg-surface-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-action"><X aria-hidden="true" className="h-4 w-4" />Cancel</button>}
          <p className="sr-only" role="status" aria-live="polite" aria-atomic="true">{isLoading ? "Checking selected sources." : ""}</p>
        </form>

        <details className="mt-5 border-y border-border py-3">
            <summary className="min-h-11 cursor-pointer py-3 text-sm font-medium text-text outline-none focus-visible:ring-2 focus-visible:ring-action">Search options</summary>
            <div className="space-y-4 pb-3">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:gap-4">
                <label htmlFor="lookup-type" className="text-sm text-text-muted">Indicator type</label>
                <select id="lookup-type" value={typeOverride} onChange={(event) => {
                  const selected = event.target.value as "auto" | LookupType;
                  invalidateView();
                  setTypeOverride(selected);
                  const next = selected === "auto" ? detectType(value) : selected;
                  setType(next);
                  setSelectedSources(defaultSources[next]);
                }} className="min-h-11 max-w-full rounded-[3px] border border-border bg-surface px-3 text-sm text-text outline-none focus-visible:ring-2 focus-visible:ring-action">
                  <option value="auto">Automatic · {typeLabels[type]}</option>
                  {Object.entries(typeLabels).map(([id, label]) => <option key={id} value={id}>{label}</option>)}
                </select>
              </div>
              <p className="text-xs leading-5 text-text-muted">Automatic detection is a guide; the request is validated before any source is called.</p>
              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3 text-xs text-text-muted">
                <span>{selectedSources.length} selected · {compatibleSources.length} compatible</span>
                <span>Choose only sources you want to query.</span>
              </div>
              {groups.map((group) => {
                const members = compatibleSources.filter((id) => SOURCE_DEFINITIONS[id].group === group.id);
                if (!members.length) return null;
                return <fieldset key={group.id} className="grid min-w-0 gap-x-5 sm:grid-cols-2">
                  <legend className="mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">{group.title}</legend>
                  {members.map((id) => {
                    const source = SOURCE_DEFINITIONS[id];
                    return <label key={id} className="flex min-h-11 cursor-pointer items-center gap-3 border-b border-border/70 py-2 text-sm text-text">
                      <input type="checkbox" checked={selectedSources.includes(id)} onChange={(event) => toggleSource(id, event.target.checked)} className="h-4 w-4 accent-action" />
                      <span>{source.name}</span>
                    </label>;
                  })}
                </fieldset>;
              })}
            </div>
        </details>
      </section>


    </div>
  );
}
