from __future__ import annotations

from email.parser import HeaderParser
from datetime import timezone
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
    "DKIM-Signature",
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
    match = re.findall(rf"{re.escape(name)}:\s*(.*?)(?=\n\S[^\n]*?:\s|\Z)", raw_headers, re.I | re.DOTALL)
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
    arc_results = parsed.get_all("ARC-Authentication-Results") or []
    received_spf = parsed.get_all("Received-SPF") or []
    dkim = parsed.get_all("DKIM-Signature") or []
    auth_text = "\n".join(auth_results)
    spf_text = "\n".join(received_spf) or auth_text

    return {
        "spf": {"verdict": _verdict_from_text(spf_text, "spf"), "headers": received_spf},
        "dkim": {"verdict": _verdict_from_text(auth_text, "dkim"), "present": bool(dkim), "headers": dkim},
        "dmarc": {"verdict": _verdict_from_text(auth_text, "dmarc")},
        "arc": {"verdict": _verdict_from_text("\n".join(arc_results), "arc"), "headers": arc_results},
        "authentication_results": auth_results,
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


def analyze_headers(raw_headers: str, country_lookup=None) -> Dict[str, Any]:
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
        })

    if not route:
        warnings.append("No parseable Received header chain found; direction analysis is limited.")

    origin = route[0]["from"] if route else None
    destination = route[-1]["by"] if route else None
    suspected_source_ip = None
    suspected_source_host = None
    for hop in route:
        suspected_source_ip = hop["from"].get("public_ip") or hop["from"].get("ip")
        suspected_source_host = hop["from"].get("host")
        if suspected_source_ip or suspected_source_host:
            break

    summary = {
        "from": get_header_value("From", raw_headers),
        "to": get_header_value("To", raw_headers),
        "cc": get_header_value("Cc", raw_headers),
        "subject": get_header_value("Subject", raw_headers),
        "message_id": get_header_value("Message-ID", raw_headers),
        "date": get_header_value("Date", raw_headers),
    }

    return {
        "summary": summary,
        "route": route,
        "direction": {
            "origin": origin,
            "destination": destination,
            "hop_count": len(route),
            "received_path": [
                {"hop": hop["hop"], "from": hop["from"].get("host"), "by": hop["by"].get("host")}
                for hop in route
            ],
            "suspected_source_ip": suspected_source_ip,
            "suspected_source_host": suspected_source_host,
        },
        "timing": {
            "total_delay_seconds": total_delay,
            "total_delay_human": human_duration(total_delay),
            "delayed": bool(total_delay),
        },
        "security": _security(parsed),
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
