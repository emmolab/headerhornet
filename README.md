# HeaderHornet

HeaderHornet is an email header analysis web app and JSON API for investigating message delivery paths, hop delays, source indicators, and authentication evidence.

This project is based on the upstream CyberDefenders Email Header Analyzer project and keeps upstream credit visible in the repository and UI.

- Upstream: https://github.com/cyberdefenders/email-header-analyzer
- Original project lineage noted by upstream: https://github.com/lnxg33k/email-header-analyzer

## What HeaderHornet does

- Parses raw RFC822 email headers.
- Builds a delivery-direction timeline from `Received` headers.
- Identifies hop delays and total transit delay.
- Extracts source/destination hosts and IP indicators.
- Adds country metadata for public IPs when GeoLite data is available.
- Summarizes sender, recipient, subject, message ID, and date.
- Extracts security/authentication evidence including SPF, DKIM, DMARC, ARC, and Authentication-Results.
- Provides both a browser UI and automation-friendly API.

## API v1

Full API documentation is available in [`docs/api-v1.md`](docs/api-v1.md), and an OpenAPI 3.0 spec is available in [`docs/openapi.yml`](docs/openapi.yml).

API key authentication is optional. Set `HEADERHORNET_API_KEY` to require clients to send either `X-API-Key` or `Authorization: Bearer` on `POST /api/v1/analyze`. Leave it empty for unauthenticated local-only deployments.

### Health

```bash
curl http://localhost:8080/api/v1/health
```

Example response:

```json
{
  "ok": true,
  "service": "headerhornet",
  "version": "1.0.0",
  "endpoints": ["/api/v1/analyze"]
}
```

### Analyze headers

Submit raw headers as JSON:

```bash
curl -s http://localhost:8080/api/v1/analyze \
  -H 'Content-Type: application/json' \
  -d @- <<'JSON'
{
  "headers": "Received: from workstation.local (unknown [198.51.100.44])\n        by mail.example.net with ESMTP id def456;\n        Tue, 04 Jun 2024 10:00:30 -0000\nAuthentication-Results: mail.example.net; spf=pass; dkim=pass; dmarc=pass\nFrom: Sender <sender@example.com>\nTo: Victim <victim@example.com>\nSubject: Test message\nDate: Tue, 04 Jun 2024 10:00:00 -0000\n"
}
JSON
```

Form submissions are also supported:

```bash
curl -s http://localhost:8080/api/v1/analyze \
  --data-urlencode headers@sample-headers.txt
```

The API returns:

- `summary`: common message headers such as From, To, Subject, Message-ID, and Date.
- `route`: ordered hop-by-hop delivery path from likely origin toward destination.
- `direction`: origin/destination, hop count, path, suspected source IP/host.
- `timing`: total delay and human-readable delay.
- `validation`: MXToolbox-style live/domain validation for DMARC, SPF, DKIM selector DNS, SPF/DKIM alignment, and DMARC compliance.
- `reputation`: per-relay IP blacklist/DNSBL status.
- `headers`: grouped raw, security, X-, and other headers.
- `warnings`: parse, validation, and reputation limitations.

See [`docs/api-example-enriched.md`](docs/api-example-enriched.md) for an enriched API response example.


## Installation

Install system dependencies:

```bash
sudo apt-get update
sudo apt-get install python3-pip python3-venv
```

Create a Python 3 virtual environment and activate it:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Run the development server:

```bash
python3 mha/server.py -d
```

You can change the bind address or port:

```bash
python3 mha/server.py -b 0.0.0.0 -p 8080
```

Then visit http://localhost:8080.

## Testing

```bash
source .venv/bin/activate
pip install pytest
pytest -q
python -m py_compile mha/server.py mha/analyzer.py
```

## Docker

A `Dockerfile` is provided if you wish to build a Docker image locally.

```bash
docker build -t headerhornet:latest .
docker run -d -p 8080:8080 headerhornet:latest
```

Published images are available from GitHub Container Registry after the repository workflow runs:

```bash
docker pull ghcr.io/emmolab/headerhornet:latest
docker run -d -p 8080:8080 ghcr.io/emmolab/headerhornet:latest
```

Branch, tag, and SHA images are also produced by `.github/workflows/docker.yml`.

## Docker Compose

Copy the example environment file, adjust the host/port/image settings, then start the service:

```bash
cp .env.example .env
docker compose up -d
```

The default `.env.example` uses:

- `HEADERHORNET_IMAGE=ghcr.io/emmolab/headerhornet:latest`
- `HEADERHORNET_HOST=127.0.0.1`
- `HEADERHORNET_HOST_PORT=8080`

Stop the service with:

```bash
docker compose down
```

Set `HEADERHORNET_DEBUG=1` in `.env` only for local development.

## Upstream credit

HeaderHornet is a maintained fork/customization of CyberDefenders Email Header Analyzer. The upstream project deserves credit for the original Flask application, parsing approach, UI foundation, and bundled static assets. Changes in this fork focus on API access, structured automation output, and product modernization.

## License

See `LICENSE.md`.
