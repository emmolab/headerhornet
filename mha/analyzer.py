from __future__ import annotations

from email.parser import HeaderParser
from email.utils import parseaddr
from datetime import timezone
import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional

import dateutil.parser
from IPy import IP


RECEIVED_SPLIT_RE = re.compile(r"Received:\s*(.*?)(?=\n\S[^\n]*?:\s|\Z)", re.IGNORECASE | re.DOTALL)
IPV4_RE = re.compile(
    r"\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b"
)

SECURITY_HEADER_NAMES = [
    "Received-SPF",
    "Authentication-Results",
    "Authentication-Results-Original",
    "DKIM-Signature",
    "ARC-Seal",
    "ARC-Authentication-Results",
]
SUMMARY_HEADERS = ["From", "To", "Cc", "Subject", "Message-ID", "Date"]


def human_duration(seconds: int, _maxweeks: int = 99999999999) -> str:
    seconds = max(int(seconds or 0), 0)
    if seconds == 0:
        return "0 sec"
    parts = [
        (seconds // 604800 % _maxweeks, "wk"),
        (seconds // 86400 % 7, "d"),
        (seconds // 3600 % 24, "hr"),
        (seconds // 60 % 60, "min"),
        (seconds % 60, "sec"),
    ]
    return ", ".join(f"{num} {unit}" for num, unit in parts if num)


def parse_date(value: str):
    if not value:
        return None
    try:
        parsed = dateutil.parser.parse(value, fuzzy=True)
    except (TypeError, ValueError):
        match = re.findall(r"^(.*?)\s*(?:\(|utc)", value, re.I)
        if not match:
            return None
        try:
            parsed = dateutil.parser.parse(match[0])
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def get_header_value(name: str, raw_headers: str) -> Optional[str]:
    parsed = HeaderParser().parsestr(raw_headers)
    value = parsed.get(name)
    if value:
        return value.strip()
    match = re.findall(rf"{re.escape(name)}:\s*(.*?)(?=\n[A-Za-z][A-Za-z0-9_.-]*:\s*|\Z)", raw_headers, re.I | re.DOTALL)
    if match:
        return " ".join(match[0].split())
    return None


def _first_public_ip(text: str) -> Optional[str]:
    for ip in IPV4_RE.findall(text or ""):
        try:
            if IP(ip).iptype() == "PUBLIC":
                return ip
        except ValueError:
            continue
    return None


def _first_ip(text: str) -> Optional[str]:
    ips = IPV4_RE.findall(text or "")
    return ips[0] if ips else None


def _host_from_segment(segment: str) -> Optional[str]:
    segment = " ".join((segment or "").split()).strip()
    if not segment:
        return None
    # Prefer the first token; it is normally the SMTP host name in Received headers.
    token = segment.split()[0].strip("()[]<>,;")
    return token or None


def _entity(segment: str, country_lookup=None) -> Dict[str, Any]:
    ip = _first_ip(segment)
    entity = {
        "raw": " ".join((segment or "").split()) or None,
        "host": _host_from_segment(segment),
        "ip": ip,
        "public_ip": _first_public_ip(segment),
    }
    if country_lookup and entity["public_ip"]:
        country = country_lookup(entity["public_ip"])
        if country:
            entity["country"] = country
    return entity


def _extract_received(raw_headers: str, parsed) -> List[str]:
    received = parsed.get_all("Received") or []
    if received:
        return [" ".join(item.split()) for item in received if ("from" in item.lower() or "by" in item.lower())]
    return [" ".join(item.split()) for item in RECEIVED_SPLIT_RE.findall(raw_headers)]


def _parse_received_line(line: str, country_lookup=None) -> Dict[str, Any]:
    line = " ".join((line or "").split())
    pre_date, _, date_part = line.rpartition(";")
    timestamp = parse_date(date_part.strip()) if date_part else None

    from_segment = ""
    by_segment = ""
    with_value = None

    match = re.search(
        r"(?:^|\s)from\s+(?P<from>.*?)\s+by\s+(?P<by>.*?)(?:\s+with\s+(?P<with>.*?))?(?:\s+id\s|\s+for\s|$)",
        pre_date,
        re.IGNORECASE,
    )
    if match:
        from_segment = match.group("from") or ""
        by_segment = match.group("by") or ""
        with_value = match.group("with")
    else:
        match = re.search(
            r"(?:^|\s)by\s+(?P<by>.*?)(?:\s+with\s+(?P<with>.*?))?(?:\s+id\s|\s+for\s|$)",
            pre_date,
            re.IGNORECASE,
        )
        if match:
            by_segment = match.group("by") or ""
            with_value = match.group("with")

    return {
        "raw": line,
        "from": _entity(from_segment, country_lookup),
        "by": _entity(by_segment, country_lookup),
        "with": " ".join(with_value.split()) if with_value else None,
        "timestamp": timestamp,
    }


def _verdict_from_text(text: str, key: str) -> Optional[str]:
    if not text:
        return None
    match = re.search(rf"\b{re.escape(key)}\s*=\s*([a-zA-Z0-9_-]+)", text, re.I)
    if match:
        return match.group(1).lower()
    if key == "spf":
        match = re.search(r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", text, re.I)
        if match:
            return match.group(1).lower()
    return None


def _security(parsed) -> Dict[str, Any]:
    auth_results = parsed.get_all("Authentication-Results") or []
    auth_results_original = parsed.get_all("Authentication-Results-Original") or []
    arc_results = parsed.get_all("ARC-Authentication-Results") or []
    arc_seals = parsed.get_all("ARC-Seal") or []
    received_spf = parsed.get_all("Received-SPF") or []
    dkim = parsed.get_all("DKIM-Signature") or []
    auth_text = "\n".join(auth_results + auth_results_original)
    spf_text = "\n".join(received_spf) or auth_text
    arc_text = "\n".join(arc_results + arc_seals)

    return {
        "spf": {"verdict": _verdict_from_text(spf_text, "spf"), "headers": received_spf},
        "dkim": {"verdict": _verdict_from_text(auth_text, "dkim"), "present": bool(dkim), "headers": dkim},
        "dmarc": {"verdict": _verdict_from_text(auth_text, "dmarc")},
        "arc": {"verdict": _verdict_from_text(arc_text, "arc") or _verdict_from_text(arc_text, "cv"), "headers": arc_results, "seals": arc_seals},
        "authentication_results": auth_results,
        "authentication_results_original": auth_results_original,
    }


def _headers_by_group(parsed) -> Dict[str, List[Dict[str, str]]]:
    security_names = {name.lower() for name in SECURITY_HEADER_NAMES}
    summary_names = {name.lower() for name in SUMMARY_HEADERS}
    grouped = {"security": [], "x": [], "other": [], "raw": []}
    for key, value in parsed.items():
        item = {"name": key, "value": value}
        grouped["raw"].append(item)
        lowered = key.lower()
        if lowered in security_names:
            grouped["security"].append(item)
        elif key.startswith("X-"):
            grouped["x"].append(item)
        elif lowered not in summary_names and lowered != "received":
            grouped["other"].append(item)
    return grouped


def _domain_from_address(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    _, address = parseaddr(value)
    if "@" not in address:
        return None
    domain = address.rsplit("@", 1)[1].strip().lower().strip(".>")
    return domain or None


def _domain_from_auth_results(text: str, key: str) -> Optional[str]:
    match = re.search(rf"\b{re.escape(key)}\s*=\s*([^\s;]+)", text or "", re.I)
    if match:
        value = match.group(1).strip().lower()
        if "@" in value:
            return value.rsplit("@", 1)[1]
        return value
    return None


def _spf_ip_from_text(text: str) -> Optional[str]:
    match = re.search(r"\bdesignates\s+([^\s)]+)", text or "", re.I)
    if match:
        ip_match = IPV4_RE.search(match.group(1))
        if ip_match:
            return ip_match.group(1)
    return _first_public_ip(text or "")


def _authenticated_source_ip(parsed) -> Optional[str]:
    auth_text = "\n".join(
        (parsed.get_all("Received-SPF") or [])
        + (parsed.get_all("Authentication-Results") or [])
        + (parsed.get_all("Authentication-Results-Original") or [])
        + (parsed.get_all("X-Forefront-Antispam-Report") or [])
        + (parsed.get_all("X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp") or [])
    )
    return _spf_ip_from_text(auth_text)


def _host_for_route_ip(route: List[Dict[str, Any]], source_ip: Optional[str]) -> Optional[str]:
    if not source_ip:
        return None
    for hop in route:
        from_entity = hop.get("from") or {}
        if source_ip in {from_entity.get("public_ip"), from_entity.get("ip")}:
            return from_entity.get("host")
    return None


def _first_route_public_endpoint(route: List[Dict[str, Any]]) -> Dict[str, Optional[str]]:
    fallback_host = None
    for hop in route:
        from_entity = hop.get("from") or {}
        fallback_host = fallback_host or from_entity.get("host")
        source_ip = from_entity.get("public_ip") or from_entity.get("ip")
        if source_ip:
            return {"ip": source_ip, "host": from_entity.get("host")}
    return {"ip": None, "host": fallback_host}


def _default_dns_lookup(name: str, record_type: str) -> List[str]:
    try:
        import dns.resolver  # type: ignore
    except Exception:
        return []

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2.0
    resolver.timeout = 1.0
    answers = resolver.resolve(name, record_type)
    records = []
    for answer in answers:
        if record_type.upper() == 'TXT':
            records.append(''.join(part.decode('utf-8', errors='replace') for part in answer.strings))
        else:
            records.append(str(answer).rstrip('.'))
    return records


def _txt_lookup(name: Optional[str], dns_lookup=None) -> List[str]:
    if not name:
        return []
    dns_lookup = dns_lookup or _default_dns_lookup
    try:
        records = dns_lookup(name.rstrip('.').lower(), 'TXT')
    except Exception:
        return []
    normalized = []
    for record in records or []:
        if isinstance(record, (list, tuple)):
            record = ''.join(str(part) for part in record)
        normalized.append(str(record).strip().strip('"'))
    return normalized


def _parse_tag_value_record(record: Optional[str]) -> Dict[str, str]:
    tags = {}
    for part in (record or '').split(';'):
        if '=' not in part:
            continue
        key, value = part.split('=', 1)
        tags[key.strip().lower()] = value.strip()
    return tags


def _dkim_signatures(parsed) -> List[Dict[str, Any]]:
    selectors = []
    for header in parsed.get_all('DKIM-Signature') or []:
        tags = _parse_tag_value_record(header)
        domain = tags.get('d')
        selector = tags.get('s')
        selectors.append({
            'domain': domain.lower() if domain else None,
            'selector': selector,
            'query': f"{selector}._domainkey.{domain}".lower() if selector and domain else None,
            'header': header,
        })
    return selectors


def _spf_record_authorizes_ip(record: str, source_ip: Optional[str]) -> Optional[bool]:
    if not record or not source_ip:
        return None
    try:
        ip = ipaddress.ip_address(source_ip)
    except ValueError:
        return None
    matched_any_ip_mechanism = False
    for token in record.split():
        token = token.strip()
        qualifier = token[0] if token and token[0] in '+-~?' else '+'
        mechanism = token[1:] if token and token[0] in '+-~?' else token
        if mechanism.startswith('ip4:'):
            matched_any_ip_mechanism = True
            cidr = mechanism[4:]
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if ip in network:
                return qualifier == '+'
    return False if matched_any_ip_mechanism else None


DNSBL_ZONES = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'b.barracudacentral.org',
]


def _default_blacklist_lookup(ip: str) -> Dict[str, Any]:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {'ip': ip, 'listed': None, 'zones': [], 'status': 'invalid_ip'}
    if address.version != 4 or not address.is_global:
        return {'ip': ip, 'listed': False, 'zones': [], 'status': 'not_listed'}

    reversed_ip = '.'.join(reversed(ip.split('.')))
    listed_zones = []
    for zone in DNSBL_ZONES:
        query = f'{reversed_ip}.{zone}'
        try:
            records = _default_dns_lookup(query, 'A')
        except Exception:
            records = []
        if records:
            listed_zones.append({'zone': zone, 'records': records})
    return {
        'ip': ip,
        'listed': bool(listed_zones),
        'zones': listed_zones,
        'status': 'listed' if listed_zones else 'not_listed',
    }


def _build_validation(parsed, summary: Dict[str, Any], direction: Dict[str, Any], security: Dict[str, Any], dns_lookup=None) -> Dict[str, Any]:
    auth_text = "\n".join(parsed.get_all('Authentication-Results') or [])
    received_spf_text = "\n".join(parsed.get_all('Received-SPF') or [])
    header_from_domain = _domain_from_address(summary.get('from'))
    mailfrom_domain = _domain_from_auth_results(auth_text, 'smtp.mailfrom') or _domain_from_address(summary.get('from'))
    spf_source_ip = _spf_ip_from_text(received_spf_text) or direction.get('suspected_source_ip')

    dmarc_query = f"_dmarc.{header_from_domain}" if header_from_domain else None
    dmarc_records = [r for r in _txt_lookup(dmarc_query, dns_lookup) if r.lower().startswith('v=dmarc1')]
    dmarc_tags = _parse_tag_value_record(dmarc_records[0] if dmarc_records else None)

    spf_records = [r for r in _txt_lookup(mailfrom_domain, dns_lookup) if r.lower().startswith('v=spf1')]
    spf_authorized = _spf_record_authorizes_ip(spf_records[0], spf_source_ip) if spf_records else None

    dkim_selectors = []
    for signature in _dkim_signatures(parsed):
        records = [r for r in _txt_lookup(signature['query'], dns_lookup) if r.lower().startswith('v=dkim1')]
        dkim_selectors.append({
            **signature,
            'record_found': bool(records),
            'records': records,
        })

    spf_verdict = security.get('spf', {}).get('verdict')
    dkim_verdict = security.get('dkim', {}).get('verdict')
    dmarc_verdict = security.get('dmarc', {}).get('verdict')
    spf_authenticated = spf_verdict == 'pass' or spf_authorized is True
    dkim_authenticated = dkim_verdict == 'pass'
    dkim_domains = [item.get('domain') for item in dkim_selectors if item.get('domain')]
    spf_aligned = bool(header_from_domain and mailfrom_domain and header_from_domain == mailfrom_domain)
    dkim_aligned = bool(header_from_domain and header_from_domain in dkim_domains)
    compliant = bool(dmarc_records) and (dmarc_verdict == 'pass' or ((spf_authenticated and spf_aligned) or (dkim_authenticated and dkim_aligned)))

    return {
        'header_from_domain': header_from_domain,
        'dmarc': {
            'query': dmarc_query,
            'record_found': bool(dmarc_records),
            'records': dmarc_records,
            'policy': dmarc_tags.get('p'),
            'subdomain_policy': dmarc_tags.get('sp'),
            'rua': dmarc_tags.get('rua'),
            'ruf': dmarc_tags.get('ruf'),
        },
        'spf': {
            'domain': mailfrom_domain,
            'source_ip': spf_source_ip,
            'record_found': bool(spf_records),
            'records': spf_records,
            'source_ip_authorized': spf_authorized,
            'header_verdict': spf_verdict,
        },
        'dkim': {
            'header_verdict': dkim_verdict,
            'selectors': dkim_selectors,
        },
        'alignment': {
            'spf': {'aligned': spf_aligned, 'from_domain': header_from_domain, 'mailfrom_domain': mailfrom_domain},
            'dkim': {'aligned': dkim_aligned, 'from_domain': header_from_domain, 'dkim_domains': dkim_domains},
        },
        'dmarc_compliance': {
            'compliant': compliant,
            'checks': {
                'spf_aligned': spf_aligned,
                'spf_authenticated': spf_authenticated,
                'dkim_aligned': dkim_aligned,
                'dkim_authenticated': dkim_authenticated,
            },
        },
    }


def _build_reputation(route: List[Dict[str, Any]], blacklist_lookup=None) -> Dict[str, Any]:
    checked = True
    relay_ips = []
    seen = set()
    lookup = blacklist_lookup or _default_blacklist_lookup
    for hop in route:
        ip = hop.get('from', {}).get('public_ip') or hop.get('from', {}).get('ip')
        if not ip or ip in seen:
            hop['blacklist'] = {'ip': ip, 'listed': None, 'zones': [], 'status': 'not_checked'}
            continue
        seen.add(ip)
        try:
            result = lookup(ip)
        except Exception:
            result = {'ip': ip, 'listed': None, 'zones': [], 'status': 'lookup_error'}
        hop['blacklist'] = result
        relay_ips.append(result)
    return {'checked': checked, 'relay_ips': relay_ips}


def _validation_warnings(validation: Dict[str, Any]) -> List[str]:
    warnings = []
    if validation['dmarc']['record_found'] is False:
        warnings.append('No DMARC record found for the Header From domain.')
    if validation['spf']['record_found'] is False:
        warnings.append('No SPF record found for the envelope/mailfrom domain.')
    if validation['dkim']['selectors'] and not any(item['record_found'] for item in validation['dkim']['selectors']):
        warnings.append('No DKIM selector DNS records found for DKIM signatures in the header.')
    if validation['dmarc_compliance']['compliant'] is False:
        warnings.append('Message does not appear DMARC compliant from available header and DNS evidence.')
    return warnings


def analyze_headers(raw_headers: str, country_lookup=None, dns_lookup=None, blacklist_lookup=None) -> Dict[str, Any]:
    if not raw_headers or not raw_headers.strip():
        raise ValueError("headers are required")

    raw_headers = raw_headers.strip()
    parsed = HeaderParser().parsestr(raw_headers)
    received_lines = _extract_received(raw_headers, parsed)
    parsed_received = [_parse_received_line(line, country_lookup) for line in received_lines]

    # Received headers are written newest first. The API returns actual travel direction:
    # earliest/origin hop first, final receiving system last.
    chronological = list(reversed(parsed_received))
    route = []
    warnings = []
    total_delay = 0
    for idx, hop in enumerate(chronological, start=1):
        next_hop = chronological[idx] if idx < len(chronological) else None
        delay = 0
        if hop["timestamp"] and next_hop and next_hop["timestamp"]:
            delay = max(int((next_hop["timestamp"] - hop["timestamp"]).total_seconds()), 0)
        total_delay += delay
        timestamp = hop["timestamp"]
        route.append({
            "hop": idx,
            "from": hop["from"],
            "by": hop["by"],
            "with": hop["with"],
            "time_utc": timestamp.isoformat().replace("+00:00", "Z") if timestamp else None,
            "delay_seconds": delay,
            "delay_human": human_duration(delay),
            "raw": hop["raw"],
            "blacklist": {"ip": hop["from"].get("public_ip") or hop["from"].get("ip"), "listed": None, "zones": [], "status": "not_checked"},
        })

    if not route:
        warnings.append("No parseable Received header chain found; direction analysis is limited.")

    origin = route[0]["from"] if route else None
    destination = route[-1]["by"] if route else None
    origin_ip = (origin or {}).get("public_ip") or (origin or {}).get("ip")
    authenticated_ip = _authenticated_source_ip(parsed)
    route_endpoint = _first_route_public_endpoint(route)
    suspected_source_ip = origin_ip or authenticated_ip or route_endpoint.get("ip")
    suspected_source_host = _host_for_route_ip(route, suspected_source_ip) or route_endpoint.get("host")

    summary = {
        "from": get_header_value("From", raw_headers),
        "to": get_header_value("To", raw_headers),
        "cc": get_header_value("Cc", raw_headers),
        "subject": get_header_value("Subject", raw_headers),
        "message_id": get_header_value("Message-ID", raw_headers),
        "date": get_header_value("Date", raw_headers),
    }

    direction = {
        "origin": origin,
        "destination": destination,
        "hop_count": len(route),
        "received_path": [
            {"hop": hop["hop"], "from": hop["from"].get("host"), "by": hop["by"].get("host")}
            for hop in route
        ],
        "suspected_source_ip": suspected_source_ip,
        "suspected_source_host": suspected_source_host,
    }
    security = _security(parsed)
    validation = _build_validation(parsed, summary, direction, security, dns_lookup=dns_lookup)
    warnings.extend(_validation_warnings(validation))
    reputation = _build_reputation(route, blacklist_lookup=blacklist_lookup)

    return {
        "summary": summary,
        "route": route,
        "direction": direction,
        "timing": {
            "total_delay_seconds": total_delay,
            "total_delay_human": human_duration(total_delay),
            "delayed": bool(total_delay),
        },
        "security": security,
        "validation": validation,
        "reputation": reputation,
        "headers": _headers_by_group(parsed),
        "warnings": warnings,
    }


def legacy_hops_for_template(analysis: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    legacy = {}
    for hop in analysis["route"]:
        legacy[hop["hop"]] = {
            "Timestmp": hop["time_utc"],
            "Time": hop["time_utc"] or "",
            "Delay": hop["delay_seconds"],
            "Direction": [
                hop["from"].get("raw") or "",
                hop["by"].get("raw") or "",
                hop.get("with") or "",
            ],
        }
    return legacy


def legacy_summary_for_template(analysis: Dict[str, Any]) -> Dict[str, Any]:
    summary = analysis["summary"]
    return {
        "From": summary.get("from"),
        "To": summary.get("to"),
        "Cc": summary.get("cc"),
        "Subject": summary.get("subject"),
        "MessageID": summary.get("message_id"),
        "Date": summary.get("date"),
    }
