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


## Development commands

```sh
pnpm typecheck
pnpm build
```



