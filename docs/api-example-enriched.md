# HeaderHornet enriched API example

This example shows the MXToolbox-style enriched response shape after the analyzer adds DMARC/SPF/DKIM validation, alignment, DMARC compliance, and relay reputation fields.

## Request

```bash
curl -s https://headerhornet.example.com/api/v1/analyze \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: YOUR_API_KEY' \
  -d '{"headers":"<raw RFC822 headers>"}'
```

## Response excerpt

```json
{
  "ok": true,
  "analysis": {
    "summary": {
      "from": "Sender <sender@sender.example>",
      "to": "Victim <victim@example.com>",
      "subject": "Test message"
    },
    "direction": {
      "hop_count": 2,
      "suspected_source_ip": "198.51.100.44",
      "suspected_source_host": "workstation.local"
    },
    "timing": {
      "total_delay_seconds": 270,
      "total_delay_human": "4 min, 30 sec"
    },
    "validation": {
      "header_from_domain": "sender.example",
      "dmarc": {
        "query": "_dmarc.sender.example",
        "record_found": true,
        "policy": "reject"
      },
      "spf": {
        "domain": "sender.example",
        "source_ip": "203.0.113.10",
        "record_found": true,
        "source_ip_authorized": true,
        "header_verdict": "pass"
      },
      "dkim": {
        "header_verdict": "pass",
        "selectors": [
          {
            "domain": "sender.example",
            "selector": "selector1",
            "query": "selector1._domainkey.sender.example",
            "record_found": true
          }
        ]
      },
      "alignment": {
        "spf": {
          "aligned": true,
          "from_domain": "sender.example",
          "mailfrom_domain": "sender.example"
        },
        "dkim": {
          "aligned": true,
          "from_domain": "sender.example",
          "dkim_domains": ["sender.example"]
        }
      },
      "dmarc_compliance": {
        "compliant": true,
        "checks": {
          "spf_aligned": true,
          "spf_authenticated": true,
          "dkim_aligned": true,
          "dkim_authenticated": true
        }
      }
    },
    "reputation": {
      "checked": true,
      "relay_ips": [
        {
          "ip": "198.51.100.44",
          "listed": false,
          "status": "not_listed",
          "zones": []
        }
      ]
    },
    "warnings": []
  }
}
```

Notes:

- `security` remains the raw header-derived SPF/DKIM/DMARC/ARC evidence.
- `validation` is the MXToolbox-style independent validation layer.
- `reputation` gives per-IP blacklist/DNSBL status, and each `route[]` hop also includes a `blacklist` object for table rendering.
