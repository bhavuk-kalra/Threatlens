import "server-only";

export type ProviderErrorStatus = "error" | "not_found" | "rate_limited" | "timeout";

export class ProviderError extends Error {
  readonly status: ProviderErrorStatus;

  constructor(status: ProviderErrorStatus, message: string) {
    super(message);
    this.name = "ProviderError";
    this.status = status;
  }
}

export const PROVIDER_HTTP_TIMEOUT_MS = 8_000;
export const PROVIDER_HTTP_MAX_RESPONSE_BYTES = 256 * 1024;

const allowedHosts = new Set([
  "www.virustotal.com",
  "api.shodan.io",
  "api.abuseipdb.com",
  "ipinfo.io",
  "urlhaus-api.abuse.ch",
  "threatfox-api.abuse.ch",
  "mb-api.abuse.ch",
  "urlscan.io",
  "otx.alienvault.com",
  "api.greynoise.io",
]);

function providerError(status: ProviderErrorStatus, message: string): ProviderError {
  return new ProviderError(status, message);
}

function assertAllowedUrl(rawUrl: string): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw providerError("error", "Provider URL is invalid.");
  }

  if (
    url.protocol !== "https:" ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.port.length > 0 ||
    !allowedHosts.has(url.hostname.toLowerCase())
  ) {
    throw providerError("error", "Provider URL is not allowed.");
  }
  return url;
}

function statusError(status: number): ProviderError {
  if (status === 404) return providerError("not_found", "Provider returned no matching record.");
  if (status === 429) return providerError("rate_limited", "Provider rate limit reached.");
  if (status === 401 || status === 403) {
    return providerError("error", "Invalid provider credentials or access is not permitted.");
  }
  return providerError("error", "Provider request failed.");
}

async function readBoundedBody(response: Response): Promise<string> {
  const contentLength = response.headers.get("content-length");
  if (contentLength && /^\d+$/.test(contentLength) && Number(contentLength) > PROVIDER_HTTP_MAX_RESPONSE_BYTES) {
    try {
      void response.body?.cancel().catch(() => {});
    } catch {
      // The size check is already decisive; cancellation errors are not useful to callers.
    }
    throw providerError("error", "Provider response exceeded the size limit.");
  }

  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let byteLength = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      byteLength += value.byteLength;
      if (byteLength > PROVIDER_HTTP_MAX_RESPONSE_BYTES) {
        try {
          void reader.cancel().catch(() => {});
        } catch {
          // Keep the bounded-size failure as the public error.
        }
        throw providerError("error", "Provider response exceeded the size limit.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(byteLength);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw providerError("error", "Provider returned an invalid response.");
  }
}

/** Fetch and parse a bounded JSON response from one of the fixed provider hosts. */
export async function fetchProviderJson(
  url: string,
  init: RequestInit = {},
  signal?: AbortSignal,
): Promise<unknown> {
  const parsedUrl = assertAllowedUrl(url);
  const abortSignals = [signal, init.signal ?? undefined].filter(
    (value): value is AbortSignal => value !== undefined,
  );
  if (abortSignals.some((item) => item.aborted)) {
    throw providerError("timeout", "Provider request was cancelled.");
  }

  const controller = new AbortController();
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  let removeAbortListeners = () => {};
  let rejectTimeout: (error: ProviderError) => void = () => {};
  const timeoutPromise = new Promise<never>((_, reject) => {
    rejectTimeout = reject;
  });
  const onAbort = () => {
    controller.abort();
  };

  for (const item of abortSignals) item.addEventListener("abort", onAbort, { once: true });
  removeAbortListeners = () => {
    for (const item of abortSignals) item.removeEventListener("abort", onAbort);
  };

  timeoutId = setTimeout(() => {
    controller.abort();
    rejectTimeout(providerError("timeout", "Provider request timed out."));
  }, PROVIDER_HTTP_TIMEOUT_MS);

  const cancelledPromise = new Promise<never>((_, reject) => {
    if (abortSignals.length === 0) return;
    const rejectCancelled = () => reject(providerError("timeout", "Provider request was cancelled."));
    for (const item of abortSignals) {
      if (item.aborted) rejectCancelled();
      else item.addEventListener("abort", rejectCancelled, { once: true });
    }
    const previousCleanup = removeAbortListeners;
    removeAbortListeners = () => {
      previousCleanup();
      for (const item of abortSignals) item.removeEventListener("abort", rejectCancelled);
    };
  });

  try {
    const request = (async () => {
      let response: Response;
      try {
        response = await fetch(parsedUrl, {
          ...init,
          cache: "no-store",
          redirect: "error",
          signal: controller.signal,
        });
      } catch {
        if (controller.signal.aborted) throw providerError("timeout", "Provider request was cancelled.");
        throw providerError("error", "Provider request failed.");
      }

      if (!response.ok) {
        try {
          void response.body?.cancel().catch(() => {});
        } catch {
          // Status mapping does not depend on reading the provider body.
        }
        throw statusError(response.status);
      }

      const body = await readBoundedBody(response);
      try {
        return JSON.parse(body) as unknown;
      } catch {
        throw providerError("error", "Provider returned invalid JSON.");
      }
    })();

    return await Promise.race([request, timeoutPromise, cancelledPromise]);
  } catch (error) {
    if (error instanceof ProviderError) throw error;
    throw providerError("error", "Provider request failed.");
  } finally {
    if (timeoutId !== undefined) clearTimeout(timeoutId);
    removeAbortListeners();
    controller.abort();
  }
}

/** Convert a scalar provider value to bounded, control-character-free display text. */
export function safeText(value: unknown, max = 200): string {
  const limit = Number.isFinite(max) ? Math.max(0, Math.min(Math.floor(max), 10_000)) : 200;
  if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") return "";
  return String(value).replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, limit);
}

/** Normalize a valid date-like value to an ISO UTC timestamp. */
export function utcDate(value: unknown): string | undefined {
  let date: Date;
  if (value instanceof Date) date = value;
  else if (typeof value === "string" || typeof value === "number") date = new Date(value);
  else return undefined;
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}
