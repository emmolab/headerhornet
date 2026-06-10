# HeaderHornet API v1

HeaderHornet exposes a small JSON API for automating email header investigations. The API is designed for SOC, MSP, MSSP, and helpdesk workflows where an analyst or ticketing automation needs a structured summary of raw RFC822 headers.

## Base URL

Local Docker default:

```text
http://localhost:8080
```

Behind a reverse proxy:

```text
https://headerhornet.example.com
```

## Authentication

API key authentication is optional and is controlled by the `HEADERHORNET_API_KEY` environment variable.

- If `HEADERHORNET_API_KEY` is empty or unset, `POST /api/v1/analyze` accepts unauthenticated requests.
- If `HEADERHORNET_API_KEY` is set, `POST /api/v1/analyze` requires a matching key.
- `GET /api/v1/health` remains unauthenticated for load balancers, Traefik, Docker health checks, and uptime monitors.

Supported client headers:

```http
X-API-Key: your-long-random-key
```

or:

```http
Authorization: Bearer TOKEN
```

Generate a production key:

```bash
openssl rand -hex 32
```

Docker Compose example:

```env
HEADERHORNET_API_KEY=replace-with-a-long-random-value
```

## Temporary API request diagnostics

For SOAR/ticketing integration debugging, HeaderHornet can log what the API received before analysis. This is disabled by default.

```env
HEADERHORNET_LOG_API_REQUESTS=1
HEADERHORNET_LOG_API_REQUEST_BODY=1
```

With only `HEADERHORNET_LOG_API_REQUESTS=1`, logs include method, path, query string, content type, redacted request headers, body lengths, line counts, and SHA-256 digests. Adding `HEADERHORNET_LOG_API_REQUEST_BODY=1` also logs the full raw request body and the normalized headers that HeaderHornet will analyze. Use body logging briefly and turn it off after collecting evidence, because raw email headers can contain personal data. `Authorization`, `X-API-Key`, and cookie headers are redacted.

After enabling the variables, recreate the container, send one test request, then collect logs:

```bash
docker compose up -d --force-recreate
docker logs --since 10m <headerhornet-container-name>
```

## Endpoints

### GET /api/v1/health

Health and service metadata endpoint. Does not require an API key.

```bash
curl -s http://localhost:8080/api/v1/health
```

Response:

```json
{
  "ok": true,
  "service": "headerhornet",
  "version": "1.0.0",
  "endpoints": ["/api/v1/analyze"]
}
```

### POST /api/v1/analyze

Analyze raw RFC822 email headers and return structured findings.

The endpoint is deliberately forgiving for analyst copy/paste workflows. It accepts:

- JSON: `{ "headers": "..." }`
- form data: `headers=<raw headers>`
- `text/plain` or `message/rfc822` raw request bodies
- common aliases: `headers`, `raw_headers`, `header_text`, or `message_headers`

Before analysis, HeaderHornet normalizes line endings, strips surrounding Markdown code fences, decodes HTML-wrapped pasted headers from tools such as Halo PSA/Outlook (`<div ...>Received: ... &lt;sender@example.com&gt;</div>`), recovers from the common invalid-JSON paste where raw multi-line headers are placed after `"headers": "` without escaping each newline, and rehydrates SOAR/ticketing-system payloads that squash headers into one long line such as `...+0000Received:` or `...trueX-Example:`.

#### Recommended copy/paste request

This is the easiest format for a human analyst because you can paste headers exactly as copied from a mail client:

```bash
curl -s http://localhost:8080/api/v1/analyze \
  -H 'X-API-Key: your-long-random-key' \
  -H 'Content-Type: text/plain' \
  --data-binary @- <<'EOF'
Received: from mail.example.net (mail.example.net [203.0.113.10])
        by mx.google.com with ESMTPS id abc123
        for <victim@example.com>;
        Tue, 04 Jun 2024 10:05:00 -0000
Received: from workstation.local (unknown [198.51.100.44])
        by mail.example.net with ESMTP id def456;
        Tue, 04 Jun 2024 10:00:30 -0000
Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=sender.example; dkim=pass header.d=sender.example; dmarc=pass header.from=sender.example
From: Sender <sender@sender.example>
To: Victim <victim@example.com>
Subject: Test message
Message-ID: <abc123@sender.example>
Date: Tue, 04 Jun 2024 10:00:00 -0000
EOF
```

#### File upload-style request

```bash
curl -s http://localhost:8080/api/v1/analyze \
  -H 'X-API-Key: your-long-random-key' \
  --data-urlencode headers@sample-headers.txt
```

#### JSON request

Use JSON when an integration can safely serialize newlines as `\n`:

```bash
curl -s http://localhost:8080/api/v1/analyze \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: your-long-random-key' \
  -d @- <<'JSON'
{
  "headers": "Received: from mail.example.net (mail.example.net [203.0.113.10])\n        by mx.google.com with ESMTPS id abc123\n        for <victim@example.com>;\n        Tue, 04 Jun 2024 10:05:00 -0000\nReceived: from workstation.local (unknown [198.51.100.44])\n        by mail.example.net with ESMTP id def456;\n        Tue, 04 Jun 2024 10:00:30 -0000\nAuthentication-Results: mx.google.com; spf=pass smtp.mailfrom=sender.example; dkim=pass header.d=sender.example; dmarc=pass header.from=sender.example\nFrom: Sender <sender@sender.example>\nTo: Victim <victim@example.com>\nSubject: Test message\nMessage-ID: <abc123@sender.example>\nDate: Tue, 04 Jun 2024 10:00:00 -0000\n"
}
JSON
```

#### Select only the fields an integration needs

By default, the API returns the full `analysis` object. To keep SOAR, ticketing, or custom integrations lightweight, request a compact result set with `fields` as either a comma-separated query string or a JSON/form field.

Supported fields and aliases. The compact response uses explicit integration-friendly result keys:

- `spf` / `spf_verdict`: returns `spf_verdict`, for example `pass` or `fail`.
- `dkim` / `dkim_verdict`: returns `dkim_verdict`.
- `dmarc` / `dmarc_verdict`: returns `dmarc_verdict`.
- `arc` / `arc_verdict`: returns `arc_verdict` when ARC evidence such as `arc=` or `cv=` is present.
- `dkim_present`: returns whether a DKIM-Signature header is present.
- `source_host`: suspected source host. Aliases: `Source Host`, `host`.
- `source_ip`: suspected source IP. Aliases: `Source IP`, `ip`.
- `hops` / `hop_count`: returns `hop_count`, the parseable Received-hop count. Aliases: `hop`, `Hop Count`.
- `blacklist_status`: first relay/source blacklist status.
- `blacklist_listed`: first relay/source blacklist listed flag.
- `reputation_checked`: whether reputation checks ran.
- `subject`: message subject.
- `direction`: compact origin/destination object. Alias: `Message Direction`.

Query-string example:

```bash
curl -s 'http://localhost:8080/api/v1/analyze?fields=spf,source_host,source_ip,hops,dmarc,dkim,arc,dkim_present,blacklist_status,blacklist_listed,reputation_checked,subject,direction' \
  -H 'X-API-Key: your-long-random-key' \
  -H 'Content-Type: text/plain' \
  --data-binary @sample-headers.txt
```

JSON example:

```bash
curl -s http://localhost:8080/api/v1/analyze \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: your-long-random-key' \
  -d @- <<'JSON'
{
  "headers": "Received: from workstation.local (unknown [198.51.100.44])\n        by mail.example.net with ESMTP id def456;\n        Tue, 04 Jun 2024 10:00:30 -0000\nAuthentication-Results: mail.example.net; spf=pass; dkim=pass; dmarc=pass\nSubject: Test message\n",
  "fields": ["SPF", "Source Host", "Source IP", "Hops", "DMARC", "DKIM", "ARC", "DKIM Present", "Blacklist Status", "Blacklist Listed", "Reputation Checked", "Subject", "Message Direction"]
}
JSON
```

Compact response example:

```json
{
  "ok": true,
  "results": {
    "spf_verdict": "pass",
    "source_host": "workstation.local",
    "source_ip": "198.51.100.44",
    "hop_count": 1,
    "dmarc_verdict": "pass",
    "dkim_verdict": "pass",
    "arc_verdict": null,
    "dkim_present": false,
    "blacklist_status": "not_listed",
    "blacklist_listed": false,
    "reputation_checked": true,
    "subject": "Test message",
    "direction": {
      "origin": {"host": "workstation.local", "ip": "198.51.100.44"},
      "destination": {"host": "mail.example.net", "ip": null}
    }
  }
}
```

## Response shape

Successful responses use this envelope:

```json
{
  "ok": true,
  "analysis": {
    "summary": {},
    "route": [],
    "direction": {},
    "timing": {},
    "security": {},
    "validation": {},
    "reputation": {},
    "headers": {},
    "warnings": []
  }
}
```

### analysis.summary

Common message headers:

- `from`
- `to`
- `cc`
- `subject`
- `message_id`
- `date`

### analysis.route

Chronological delivery path from likely origin to final receiving system. Each hop includes:

- `hop`: 1-based hop number.
- `from`: parsed source entity with raw text, host, IP, public IP, and optional country.
- `by`: parsed receiving entity with raw text, host, IP, public IP, and optional country.
- `with`: transport protocol, when parseable.
- `time_utc`: hop timestamp normalized to UTC.
- `delay_seconds`: delay until the next hop.
- `delay_human`: human-readable delay.
- `raw`: original Received header text.

### analysis.direction

High-level routing indicators:

- `origin`: first parsed source entity.
- `destination`: final parsed receiving entity.
- `hop_count`: number of parseable Received hops.
- `received_path`: compact path list.
- `suspected_source_ip`: first source IP indicator.
- `suspected_source_host`: first source host indicator.

### analysis.timing

Transit timing indicators:

- `total_delay_seconds`
- `total_delay_human`
- `delayed`

### analysis.security

Authentication and anti-spoofing evidence from headers:

- `spf.verdict` and `spf.headers`
- `dkim.verdict`, `dkim.present`, and `dkim.headers`
- `dmarc.verdict`
- `arc.verdict` and `arc.headers`
- `authentication_results`

These values are parsed from the submitted headers.

### analysis.validation

MXToolbox-style live/domain checks derived from the header and DNS:

- `header_from_domain`: RFC5322 From domain.
- `dmarc`: `_dmarc.<domain>` lookup, discovered records, policy, subdomain policy, and report URIs.
- `spf`: SPF domain, source IP, discovered SPF records, and whether the source IP is directly authorized by an `ip4` mechanism.
- `dkim`: DKIM header verdict and selector DNS lookup results.
- `alignment`: SPF and DKIM alignment against the RFC5322 From domain.
- `dmarc_compliance`: summary booleans for SPF authenticated/aligned, DKIM authenticated/aligned, and overall compliance.

### analysis.reputation

Per-relay IP reputation checks. Each route hop also includes a `blacklist` object so UI/API consumers can show MXToolbox-style per-hop blacklist status.

- `checked`: whether relay reputation checks were attempted.
- `relay_ips`: unique source/relay IP status entries with `listed`, `zones`, and `status`.

### analysis.headers

Grouped parsed headers:

- `raw`: all parsed headers.
- `security`: security-related headers.
- `x`: `X-*` headers.
- `other`: remaining non-summary, non-Received headers.

## Error responses

### Missing API key

Returned only when `HEADERHORNET_API_KEY` is configured.

```json
{
  "ok": false,
  "error": {
    "code": "unauthorized",
    "message": "A valid API key is required."
  }
}
```

HTTP status: `401`

### Missing headers

```json
{
  "ok": false,
  "error": {
    "code": "missing_headers",
    "message": "headers are required; send JSON {\"headers\":\"...\"} or form field headers"
  }
}
```

HTTP status: `400`

### Invalid headers

```json
{
  "ok": false,
  "error": {
    "code": "invalid_headers",
    "message": "headers are required"
  }
}
```

HTTP status: `400`

## Integration examples

### n8n / workflow automation

1. Add an HTTP Request node.
2. Method: `POST`.
3. URL: `https://headerhornet.example.com/api/v1/analyze`.
4. Authentication: Header Auth.
5. Header name: `X-API-Key`.
6. Header value: your configured `HEADERHORNET_API_KEY`.
7. JSON body: `{ "headers": "{{$json.rawHeaders}}" }`.

### PSA / ticket enrichment

Use the API to add structured notes to a ticket after a user reports a suspicious email:

- Subject and sender from `analysis.summary`.
- Suspected source IP/host from `analysis.direction`.
- Total delay from `analysis.timing`.
- SPF/DKIM/DMARC verdicts from `analysis.security`.
- Hop table from `analysis.route`.

### SIEM / SOAR enrichment

Recommended enrichment fields:

```json
{
  "email.headerhornet.subject": "analysis.summary.subject",
  "email.headerhornet.from": "analysis.summary.from",
  "email.headerhornet.source_ip": "analysis.direction.suspected_source_ip",
  "email.headerhornet.source_host": "analysis.direction.suspected_source_host",
  "email.headerhornet.hop_count": "analysis.direction.hop_count",
  "email.headerhornet.total_delay_seconds": "analysis.timing.total_delay_seconds",
  "email.headerhornet.spf": "analysis.security.spf.verdict",
  "email.headerhornet.dkim": "analysis.security.dkim.verdict",
  "email.headerhornet.dmarc": "analysis.security.dmarc.verdict"
}
```
