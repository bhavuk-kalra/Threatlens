import { NextResponse } from "next/server";
import { lookupRequestSchema, lookupResultSchema } from "@/lib/contracts";
import { lookupSelectedSources } from "@/lib/server/lookup";

const MAX_REQUEST_BYTES = 4_096;
const PRIVATE_NO_STORE = "private, no-store, max-age=0";

function json(body: unknown, status = 200): NextResponse {
  return NextResponse.json(body, { status, headers: { "Cache-Control": PRIVATE_NO_STORE } });
}

async function readLimitedBody(request: Request): Promise<{ text?: string; status?: number }> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength && /^\d+$/.test(declaredLength) && Number(declaredLength) > MAX_REQUEST_BYTES) {
    return { status: 413 };
  }
  if (!request.body) return { status: 400 };

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let byteLength = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      byteLength += value.byteLength;
      if (byteLength > MAX_REQUEST_BYTES) {
        try {
          await reader.cancel();
        } catch {
          // Oversize remains the safe public result.
        }
        return { status: 413 };
      }
      chunks.push(value);
    }
  } catch {
    return { status: 400 };
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(byteLength);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return { text: new TextDecoder("utf-8", { fatal: true }).decode(bytes) };
  } catch {
    return { status: 400 };
  }
}

export async function POST(request: Request): Promise<NextResponse> {
  const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") return json({ error: "Content-Type must be application/json." }, 415);

  const body = await readLimitedBody(request);
  if (body.status === 413) return json({ error: "Request body exceeds the 4096-byte limit." }, 413);
  if (body.text === undefined) return json({ error: "Request body must contain valid JSON." }, 400);

  let decoded: unknown;
  try {
    decoded = JSON.parse(body.text) as unknown;
  } catch {
    return json({ error: "Request body must contain valid JSON." }, 400);
  }

  const parsed = lookupRequestSchema.safeParse(decoded);
  if (!parsed.success || !parsed.data.sourceIds || parsed.data.sourceIds.length < 1 || parsed.data.sourceIds.length > 10) {
    return json({ error: "Provide a valid lookup and 1 to 10 unique source IDs." }, 400);
  }

  const sourceIds = parsed.data.sourceIds;
  const sources = await lookupSelectedSources(parsed.data, sourceIds, request.signal);
  const result = lookupResultSchema.safeParse({
    type: parsed.data.type,
    value: parsed.data.value,
    lookedUpAt: new Date().toISOString(),
    mode: "live",
    sources,
  });
  if (!result.success) return json({ error: "Lookup results could not be validated." }, 500);
  return json(result.data);
}
