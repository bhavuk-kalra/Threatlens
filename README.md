# ThreatLens - Threat Intelligence Lookup Platform

A production-ready threat intelligence platform that provides comprehensive lookups for IP addresses, domains, and file hashes using multiple threat intelligence APIs.

## Features

- **IP Address Lookup**: Get geolocation, open ports, reputation data, and abuse reports
- **Domain Lookup**: Retrieve WHOIS information, malware detection stats, and domain reputation
- **File Hash Lookup**: Check MD5, SHA-1, SHA-256, and SHA-512 hashes for malware detection
- **Real-time API Integration**: Integrates with VirusTotal, Shodan, AbuseIPDB, and IPInfo
- **Production-ready**: Includes input validation, rate limiting, error handling, and security features
- **Modern UI**: Built with Next.js 15, React 19, and Tailwind CSS

## Prerequisites

- Node.js 18+ 
- npm, yarn, or pnpm
- API keys from threat intelligence providers (see Configuration section)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd threatlens-3
```

2. Install dependencies:
```bash
npm install
# or
yarn install
# or
pnpm install
```

3. Configure environment variables (see Configuration section below)

4. Run the development server:
```bash
npm run dev
# or
yarn dev
# or
pnpm dev
```

5. Open [http://localhost:3000](http://localhost:3000) in your browser

## Configuration

### Environment Variables

Copy `.env.example` to `.env.local` and configure your API keys:

```bash
cp .env.example .env.local
```

### Required API Keys

For production use, you need at least one API key. VirusTotal is recommended as the minimum requirement:

#### VirusTotal (Required for production)
- Sign up at: https://www.virustotal.com/gui/my-apikey
- Free tier: 1,000 requests/day
- Add to `.env.local`: `VIRUSTOTAL_API_KEY=your_api_key_here`

#### Optional but Recommended APIs

#### Shodan
- Sign up at: https://account.shodan.io/
- Free tier: 100 queries/month
- Add to `.env.local`: `SHODAN_API_KEY=your_api_key_here`

#### AbuseIPDB
- Sign up at: https://www.abuseipdb.com/api
- Free tier: 1,000 requests/day
- Add to `.env.local`: `ABUSEIPDB_API_KEY=your_api_key_here`

#### IPInfo
- Sign up at: https://ipinfo.io/signup
- Free tier: 50,000 requests/month
- Add to `.env.local`: `IPINFO_API_KEY=your_api_key_here`

### Rate Limiting Configuration

Configure rate limiting in your environment variables:

```bash
# Rate limit window in milliseconds (default: 15 minutes)
RATE_LIMIT_WINDOW_MS=900000

# Maximum requests per window (default: 100)
RATE_LIMIT_MAX_REQUESTS=100
```

## Production Deployment

### Environment Setup

1. Set `NODE_ENV=production` in your environment
2. Configure all required API keys
3. Set up proper rate limiting based on your API quotas
4. Configure CORS and security headers as needed

### Build for Production

```bash
npm run build
npm start
```

### Docker Deployment (Optional)

Create a `Dockerfile`:

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

EXPOSE 3000

CMD ["npm", "start"]
```

Build and run:

```bash
docker build -t threatlens .
docker run -p 3000:3000 --env-file .env.local threatlens
```

## API Endpoints

### IP Lookup
```
POST /api/lookup/ip
Content-Type: application/json

{
  "ip": "8.8.8.8"
}
```

### Domain Lookup
```
POST /api/lookup/domain
Content-Type: application/json

{
  "domain": "example.com"
}
```

### Hash Lookup
```
POST /api/lookup/hash
Content-Type: application/json

{
  "hash": "44d88612fea8a8f36de82e1278abb02f"
}
```

### Configuration Check
```
GET /api/config
```

## Input Validation

The platform includes comprehensive input validation:

- **IP Addresses**: Validates IPv4 format and rejects private/reserved ranges
- **Domains**: Validates domain format, TLD requirements, and label restrictions
- **Hashes**: Supports MD5 (32), SHA-1 (40), SHA-256 (64), and SHA-512 (128) character hashes

## Security Features

- **Rate Limiting**: Prevents API abuse with configurable limits
- **Input Validation**: Comprehensive validation using Zod schemas
- **Error Handling**: Secure error messages that don't leak sensitive information
- **API Timeouts**: Prevents hanging requests with configurable timeouts
- **CORS Protection**: Configurable CORS policies

## Error Handling

The platform provides user-friendly error messages while logging detailed errors for debugging:

- **400 Bad Request**: Invalid input format
- **429 Too Many Requests**: Rate limit exceeded
- **503 Service Unavailable**: API keys not configured or external service unavailable
- **500 Internal Server Error**: Unexpected server errors

## Development

### Project Structure

```
├── app/                    # Next.js app directory
│   ├── api/               # API routes
│   │   ├── config/        # Configuration endpoint
│   │   └── lookup/        # Lookup endpoints
│   ├── globals.css        # Global styles
│   ├── layout.tsx         # Root layout
│   └── page.tsx          # Home page
├── components/            # React components
│   ├── ui/               # UI components
│   ├── lookup-form.tsx   # Main lookup form
│   └── results-display.tsx # Results display
├── lib/                  # Utility libraries
│   ├── api-config.ts     # API configuration
│   ├── lookup-service.ts # Lookup service
│   ├── utils.ts          # General utilities
│   └── validation.ts     # Input validation schemas
└── public/               # Static assets
```

### Adding New APIs

1. Add API configuration to `lib/api-config.ts`
2. Create fetch function in the appropriate API route
3. Update validation schemas if needed
4. Add error handling for the new API
5. Update the UI to display new data fields

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Check the documentation above
- Review the API provider documentation for API-specific issues
- Open an issue in the repository for bugs or feature requests

## Changelog

### v1.0.0
- Initial production release
- Complete input validation system
- Rate limiting implementation
- Comprehensive error handling
- Support for VirusTotal, Shodan, AbuseIPDB, and IPInfo APIs
- Production-ready security features
