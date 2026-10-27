import { NextResponse } from "next/server";

export function GET(): NextResponse {
  return NextResponse.json(
    { liveEnabled: true },
    { headers: { "Cache-Control": "private, no-store, max-age=0" } },
  );
}
