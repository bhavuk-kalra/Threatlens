import { lookupRequestSchema, lookupResultSchema, type LookupResult } from "./contracts";

export class LookupError extends Error {
  constructor(message: string, public readonly code: "INVALID_INPUT" | "HTTP_ERROR" | "INVALID_RESPONSE" | "ABORTED" | "NETWORK_ERROR") {
    super(message);
    this.name = "LookupError";
  }
}

export async function lookup(request: unknown, signal?: AbortSignal): Promise<LookupResult> {
  const parsedRequest = lookupRequestSchema.safeParse(request);
  if (!parsedRequest.success || !parsedRequest.data.sourceIds?.length) {
    throw new LookupError(parsedRequest.success ? "Choose at least one source." : parsedRequest.error.issues[0]?.message ?? "Enter a valid identifier.", "INVALID_INPUT");
  }

  let response: Response;
  try {
    response = await fetch("/api/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parsedRequest.data),
      signal,
    });
  } catch {
    if (signal?.aborted) throw new LookupError("Lookup cancelled.", "ABORTED");
    throw new LookupError("Could not reach the lookup service. Try again.", "NETWORK_ERROR");
  }

  if (!response.ok) {
    const message = response.status === 403
      ? "Live lookups are disabled in this environment."
      : response.status === 429
        ? "The lookup service is busy. Try again later."
        : "The lookup service could not complete this request.";
    throw new LookupError(message, "HTTP_ERROR");
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new LookupError("The lookup service returned an invalid response.", "INVALID_RESPONSE");
  }

  const parsedResult = lookupResultSchema.safeParse(payload);
  if (
    !parsedResult.success
    || parsedResult.data.mode !== "live"
    || parsedResult.data.type !== parsedRequest.data.type
    || parsedResult.data.value !== parsedRequest.data.value
    || parsedResult.data.sources.some((source) => !parsedRequest.data.sourceIds!.includes(source.id))
    || new Set(parsedResult.data.sources.map((source) => source.id)).size !== parsedResult.data.sources.length
  ) {
    throw new LookupError("The lookup service returned an invalid response.", "INVALID_RESPONSE");
  }
  return parsedResult.data;
}
