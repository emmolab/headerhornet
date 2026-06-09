from flask import Flask
from flask import jsonify
from flask import render_template
from flask import request

from email.parser import HeaderParser
import argparse
import hmac
import json
import os
import re

import geoip2.database
import pygal
from pygal.style import Style
from IPy import IP

try:
    from mha.analyzer import (
        SECURITY_HEADER_NAMES,
        analyze_headers,
        human_duration,
        legacy_hops_for_template,
        legacy_summary_for_template,
    )
except ModuleNotFoundError:  # Support running `python server.py` from inside ./mha and legacy Dockerfile layout.
    from analyzer import (  # type: ignore
        SECURITY_HEADER_NAMES,
        analyze_headers,
        human_duration,
        legacy_hops_for_template,
        legacy_summary_for_template,
    )

app = Flask(__name__)
reader = geoip2.database.Reader('%s/data/GeoLite2-Country.mmdb' % app.static_folder)


def get_country_for_ip_or_line(value):
    ipv4_address = re.compile(r"""
        \b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
        (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
        (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
        (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))\b""", re.X)
    ip = ipv4_address.findall(value or '')
    if not ip:
        return {}
    ip = ip[0]
    try:
        if IP(ip).iptype() != 'PUBLIC':
            return {}
        country = reader.country(ip).country
    except Exception:
        return {}
    if country.iso_code and country.name:
        return {
            'iso_code': country.iso_code.lower(),
            'country_name': country.name,
        }
    return {}


@app.context_processor
def country_processor():
    return dict(country=get_country_for_ip_or_line)


@app.context_processor
def duration_processor():
    return dict(duration=human_duration)


def _build_delay_chart(analysis):
    custom_style = Style(
        background='transparent',
        plot_background='transparent',
        font_family='googlefont:Open Sans',
    )
    line_chart = pygal.HorizontalBar(
        style=custom_style, height=250, legend_at_bottom=True,
        tooltip_border_radius=10)
    line_chart.tooltip_fancy_mode = False
    line_chart.title = 'Total Delay is: %s' % analysis['timing']['total_delay_human']
    line_chart.x_title = 'Delay in seconds.'
    for hop in analysis['route']:
        label = hop['from'].get('host') or hop['by'].get('host') or 'Hop %s' % hop['hop']
        prefix = 'From' if hop['from'].get('host') else 'By'
        line_chart.add('%s: %s' % (prefix, label), hop['delay_seconds'])
    return line_chart.render(is_unicode=True)


def _looks_like_headers(value):
    if not isinstance(value, str):
        return False
    return bool(re.search(r'(?im)^(received|from|to|subject|date|message-id|authentication-results|dkim-signature):', value))


def _strip_markdown_fence(value):
    text = value.strip()
    match = re.match(r'^```(?:[a-zA-Z0-9_-]+)?\s*\n(?P<body>.*)\n```\s*$', text, re.S)
    return match.group('body') if match else value


def _extract_headers_wrapper(value):
    text = value.strip()

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        for key in ('headers', 'raw_headers', 'header_text', 'message_headers'):
            if isinstance(payload.get(key), str):
                return payload[key]

    # Recover from the common copy/paste mistake where raw multi-line headers are
    # placed after `"headers": "` without JSON escaping each newline.
    match = re.match(r'^\s*\{?\s*["\']?(?:headers|raw_headers|header_text|message_headers)["\']?\s*:\s*["\']?\s*(?P<body>.*)\s*$', text, re.S | re.I)
    if not match:
        return value

    body = match.group('body').strip()
    body = re.sub(r'\s*["\']?\s*}\s*$', '', body, count=1)
    body = body.strip().strip('"\'')
    return body if _looks_like_headers(body) else value


def _decode_literal_newline_headers(value):
    text = value.strip()
    if '\\n' not in text:
        return value
    if text.count('\\n') < text.count('\n'):
        return value
    try:
        decoded = json.loads('"' + text.replace('"', '\\"') + '"')
    except json.JSONDecodeError:
        return value
    return decoded if _looks_like_headers(decoded) else value


def _sanitize_header_input(value):
    if not isinstance(value, str):
        return ''

    text = value.replace('\r\n', '\n').replace('\r', '\n').strip()
    text = _strip_markdown_fence(text)
    text = _extract_headers_wrapper(text)
    text = _strip_markdown_fence(text)
    text = _decode_literal_newline_headers(text)
    return text.strip()


def _headers_from_request():
    payload = request.get_json(silent=True) or {}
    headers = None
    if isinstance(payload, dict):
        for key in ('headers', 'raw_headers', 'header_text', 'message_headers'):
            if payload.get(key):
                headers = payload.get(key)
                break

    if not headers:
        for key in ('headers', 'raw_headers', 'header_text', 'message_headers'):
            if request.form.get(key):
                headers = request.form.get(key)
                break

    if not headers:
        raw_body = request.get_data(as_text=True)
        if request.mimetype in {'text/plain', 'message/rfc822', 'application/octet-stream'} or _looks_like_headers(raw_body):
            headers = raw_body

    return _sanitize_header_input(headers)


_FIELD_ALIASES = {
    'spf': 'spf',
    'source_ip': 'source_ip',
    'sourceip': 'source_ip',
    'ip': 'source_ip',
    'hops': 'hops',
    'hop': 'hops',
    'hop_count': 'hops',
    'hopcount': 'hops',
    'dmarc': 'dmarc',
    'dkim': 'dkim',
    'subject': 'subject',
    'direction': 'direction',
    'message_direction': 'direction',
    'messagedirection': 'direction',
}


def _field_key(value):
    key = re.sub(r'[^a-z0-9]+', '_', str(value).strip().lower()).strip('_')
    return _FIELD_ALIASES.get(key)


def _split_requested_fields(value):
    if not value:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(',') if part.strip()]
    if isinstance(value, (list, tuple)):
        fields = []
        for item in value:
            fields.extend(_split_requested_fields(item))
        return fields
    return [str(value).strip()]


def _requested_fields_from_request():
    requested = []
    for value in request.args.getlist('fields') + request.args.getlist('field'):
        requested.extend(_split_requested_fields(value))

    payload = request.get_json(silent=True) or {}
    if isinstance(payload, dict):
        requested.extend(_split_requested_fields(payload.get('fields')))
        requested.extend(_split_requested_fields(payload.get('field')))

    requested.extend(_split_requested_fields(request.form.get('fields')))
    requested.extend(_split_requested_fields(request.form.get('field')))

    canonical = []
    unknown = []
    for field in requested:
        key = _field_key(field)
        if not key:
            unknown.append(field)
            continue
        if key not in canonical:
            canonical.append(key)
    return canonical, unknown


def _endpoint_summary(endpoint):
    endpoint = endpoint or {}
    return {
        'host': endpoint.get('host'),
        'ip': endpoint.get('public_ip') or endpoint.get('ip'),
    }


def _selected_analysis_fields(analysis, fields):
    security = analysis.get('security') or {}
    direction = analysis.get('direction') or {}
    summary = analysis.get('summary') or {}
    selected = {}

    for field in fields:
        if field == 'spf':
            selected[field] = (security.get('spf') or {}).get('verdict')
        elif field == 'source_ip':
            selected[field] = direction.get('suspected_source_ip')
        elif field == 'hops':
            selected[field] = direction.get('hop_count')
        elif field == 'dmarc':
            selected[field] = (security.get('dmarc') or {}).get('verdict')
        elif field == 'dkim':
            selected[field] = (security.get('dkim') or {}).get('verdict')
        elif field == 'subject':
            selected[field] = summary.get('subject')
        elif field == 'direction':
            selected[field] = {
                'origin': _endpoint_summary(direction.get('origin')),
                'destination': _endpoint_summary(direction.get('destination')),
            }
    return selected


def _configured_api_key():
    return os.environ.get('HEADERHORNET_API_KEY', '').strip()


def _submitted_api_key():
    header_key = request.headers.get('X-API-Key', '').strip()
    if header_key:
        return header_key

    authorization = request.headers.get('Authorization', '').strip()
    scheme, _, token = authorization.partition(' ')
    if scheme.lower() == 'bearer' and token:
        return token.strip()
    return ''


def _require_api_key():
    expected = _configured_api_key()
    if not expected:
        return None

    submitted = _submitted_api_key()
    if submitted and hmac.compare_digest(submitted, expected):
        return None

    return jsonify({
        'ok': False,
        'error': {
            'code': 'unauthorized',
            'message': 'A valid API key is required.',
        },
    }), 401


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        mail_data = request.form['headers'].strip()
        analysis = analyze_headers(mail_data, country_lookup=get_country_for_ip_or_line)
        data = legacy_hops_for_template(analysis)
        summary = legacy_summary_for_template(analysis)
        chart = _build_delay_chart(analysis)
        security_headers = SECURITY_HEADER_NAMES
        parsed_headers = HeaderParser().parsestr(mail_data)
        return render_template(
            'index.html', data=data, delayed=analysis['timing']['delayed'],
            summary=summary, n=parsed_headers, chart=chart,
            security_headers=security_headers, analysis=analysis)
    return render_template('index.html')


@app.route('/api/v1/health', methods=['GET'])
def api_health():
    return jsonify({
        'ok': True,
        'service': 'headerhornet',
        'version': '1.0.0',
        'endpoints': ['/api/v1/analyze'],
    })


@app.route('/api/v1/analyze', methods=['POST'])
def api_analyze():
    auth_error = _require_api_key()
    if auth_error:
        return auth_error

    headers = _headers_from_request()
    if not headers:
        return jsonify({
            'ok': False,
            'error': {
                'code': 'missing_headers',
                'message': 'headers are required; send JSON {"headers":"..."} or form field headers',
            },
        }), 400

    requested_fields, unknown_fields = _requested_fields_from_request()
    if unknown_fields:
        return jsonify({
            'ok': False,
            'error': {
                'code': 'invalid_fields',
                'message': 'Unknown field(s): %s. Supported fields are: spf, source_ip, hops, dmarc, dkim, subject, direction.' % ', '.join(unknown_fields),
            },
        }), 400

    try:
        analysis = analyze_headers(headers, country_lookup=get_country_for_ip_or_line)
    except ValueError as exc:
        return jsonify({'ok': False, 'error': {'code': 'invalid_headers', 'message': str(exc)}}), 400

    if requested_fields:
        return jsonify({'ok': True, 'results': _selected_analysis_fields(analysis, requested_fields)})

    return jsonify({'ok': True, 'analysis': analysis})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Mail Header Analyser")
    parser.add_argument("-d", "--debug", action="store_true", default=False,
                        help="Enable debug mode")
    parser.add_argument("-b", "--bind", default="127.0.0.1", type=str)
    parser.add_argument("-p", "--port", default="8080", type=int)
    args = parser.parse_args()

    env_debug = os.environ.get('HEADERHORNET_DEBUG', '').lower() in {'1', 'true', 'yes', 'on'}
    app.debug = args.debug or env_debug
    app.run(host=args.bind, port=args.port)
