from flask import Flask
from flask import jsonify
from flask import render_template
from flask import request

from email.parser import HeaderParser
import argparse
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


def _headers_from_request():
    payload = request.get_json(silent=True) or {}
    headers = payload.get('headers') if isinstance(payload, dict) else None
    if not headers:
        headers = request.form.get('headers')
    return headers.strip() if isinstance(headers, str) else ''


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
            security_headers=security_headers)
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
    headers = _headers_from_request()
    if not headers:
        return jsonify({
            'ok': False,
            'error': {
                'code': 'missing_headers',
                'message': 'headers are required; send JSON {"headers":"..."} or form field headers',
            },
        }), 400

    try:
        analysis = analyze_headers(headers, country_lookup=get_country_for_ip_or_line)
    except ValueError as exc:
        return jsonify({'ok': False, 'error': {'code': 'invalid_headers', 'message': str(exc)}}), 400

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
