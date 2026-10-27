# ThreatLens

ThreatLens is a personal threat-intelligence lookup tool. It checks a selected IP address, domain, or file hash against selected sources and presents their evidence and status separately. It does not calculate a combined risk score or make an automated verdict.

The application is live-request only: it contains no example reports, fabricated findings, lookup history, result cache, or user accounts. Provider rate limits are handled by the upstream services.

## What it supports

- Public IPv4 addresses, domains, and MD5/SHA-1/SHA-256 hashes.
- Ten selectable sources, with defaults chosen for each identifier type.
- Field Notes interface: one live search, source selection, single-column evidence notes, expandable source details, and collapsed coverage for all ten sources.
- Source-level errors, no-record states, unsupported types, timestamps, provider links, and partial results.

A source returning no record or no detections does not establish that an indicator is safe. Sources have different coverage and freshness, and some feeds share data.

## Run locally

Requirements: Node.js 20 or newer and pnpm 11.

```sh
pnpm install --frozen-lockfile
cp .env.example .env.local
pnpm dev
```

Open `http://localhost:3000`. Add the provider keys you want to use to `.env.local`, then restart the development server. Each submission sends the entered identifier only to the providers selected for that lookup. Provider terms and quotas apply. Avoid using private, sensitive, or third-party indicators unless you are permitted to share them with those providers.

## API keys and deployment

Local secrets belong in the ignored `.env.local` file. Never commit it, paste keys into client code, use a `NEXT_PUBLIC_` prefix for a provider key, or include a key in a URL, log, screenshot, or issue. `.env.example` contains names only.

On Vercel, configure provider API keys in **Settings → Environment Variables** as **Secret** values. Scope them to Production (and Preview only if you want preview deployments to use the same provider accounts), save, then redeploy. Environment changes apply only to new deployments. See [Vercel environment variables](https://vercel.com/docs/environment-variables) and [Vercel's Config and Secret types](https://vercel.com/changelog/environment-variables-now-use-config-and-secret-types).

If a key was committed, shared, or exposed in a screenshot, rotate it with the provider. Do not rely on deleting the visible copy.

## Current provider configuration

Copy `.env.example` to `.env.local`. Configure only the sources you intend to use:

| Variable | Source |
| --- | --- |
| `VIRUSTOTAL_API_KEY` | VirusTotal |
| `SHODAN_API_KEY` | Shodan |
| `ABUSEIPDB_API_KEY` | AbuseIPDB |
| `IPINFO_API_KEY` | IPinfo legacy JSON API |
| `ABUSECH_AUTH_KEY` | Shared by URLhaus, ThreatFox, and MalwareBazaar |
| `URLSCAN_API_KEY` | urlscan.io |
| `OTX_API_KEY` | LevelBlue OTX |
| `GREYNOISE_API_KEY` | GreyNoise Community (optional; anonymous lookups have a smaller quota) |

The exact lookup scope, free-use terms, and current limits can change. Check each provider's official terms before enabling or relying on a source.

## Development commands

```sh
pnpm typecheck
pnpm build
```

Real provider credentials, account entitlements, production environment values, and a deployed live smoke test still require owner setup.

## Architecture

- `app/api/lookup/route.ts` is the single validated lookup route. It enforces a small request-body limit, validates selected sources, and returns private non-cacheable responses.
- `app/api/config/route.ts` returns only a safe live-readiness boolean.
- `lib/contracts.ts` contains browser-safe schemas and shared source definitions.
- `lib/server/` contains server-only provider adapters, fixed HTTPS destinations, bounded response parsing, and provider-key access.
- `components/lookup-form.tsx` handles live search, source selection, and request cancellation; `components/results-display.tsx` renders editorial case notes without a composite verdict.
- The Field Notes interface uses locally bundled Instrument Sans and IBM Plex Mono fonts with OFL notices in `app/fonts`, and follows the system's light/dark appearance.

There is no authentication, result cache, investigation history, or AI-generated summary. A future optional AI summary or Jev classification would need a separate design, explicit provider-data disclosures, source attribution, and evaluation; it must not replace the underlying evidence or claim certainty.
