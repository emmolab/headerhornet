import logging

from tests.test_analyzer import SAMPLE_HEADERS
from mha.server import app, _sanitize_header_input


def test_analyze_api_accepts_json_headers():
    client = app.test_client()

    response = client.post('/api/v1/analyze', json={'headers': SAMPLE_HEADERS})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['ok'] is True
    assert payload['analysis']['direction']['hop_count'] == 2
    assert payload['analysis']['security']['spf']['verdict'] == 'pass'


def test_analyze_api_accepts_form_headers():
    client = app.test_client()

    response = client.post('/api/v1/analyze', data={'headers': SAMPLE_HEADERS})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['analysis']['summary']['subject'] == 'Test message'


def test_analyze_api_accepts_text_plain_raw_headers():
    client = app.test_client()

    response = client.post(
        '/api/v1/analyze',
        data=SAMPLE_HEADERS,
        content_type='text/plain',
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['ok'] is True
    assert payload['analysis']['summary']['subject'] == 'Test message'


def test_analyze_api_sanitizes_pasted_invalid_json_header_wrapper():
    client = app.test_client()
    pasted_body = '{\n  "headers": "\n' + SAMPLE_HEADERS + '\n"\n}'

    response = client.post(
        '/api/v1/analyze',
        data=pasted_body,
        content_type='text/plain',
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['analysis']['direction']['hop_count'] == 2
    assert payload['analysis']['summary']['subject'] == 'Test message'


def test_analyze_api_sanitizes_markdown_fenced_headers():
    client = app.test_client()
    pasted_body = '```\n' + SAMPLE_HEADERS + '\n```'

    response = client.post(
        '/api/v1/analyze',
        data=pasted_body,
        content_type='text/plain',
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['analysis']['summary']['from'] == 'Sender <sender@sender.example>'


def test_analyze_api_decodes_halo_html_wrapped_squashed_headers():
    client = app.test_client()
    halo_headers = (
        '<div tabindex="-1" data-pasted="true"><div tabindex="0">'
        'Received: from SY8PR01MB9220.ausprd01.prod.outlook.com (::1) by '
        'SY7PR01MB9171.ausprd01.prod.outlook.com with HTTPS; Thu, 4 Jun 2026 00:41:35 +0000'
        'Received: from SY1PEPF000066C2.ausprd01.prod.outlook.com (2603:10c6:10:246:cafe::4b) by '
        'SY5PR01CA0112.outlook.office365.com (2603:10c6:10:246::11) with Microsoft SMTP Server; '
        'Thu, 4 Jun 2026 00:41:25 +0000'
        'Authentication-Results: spf=pass (sender IP is 13.70.157.244) '
        'smtp.mailfrom=sender.example; dkim=none (message not signed) header.d=none;'
        'dmarc=pass action=none header.from=sender.example;'
        'Received-SPF: Pass (protection.outlook.com: domain of sender.example designates '
        '13.70.157.244 as permitted sender) receiver=protection.outlook.com; '
        'client-ip=13.70.157.244; helo=au2.smtp.exclaimer.net; pr=C'
        'Received: from au2.smtp.exclaimer.net (13.70.157.244) by '
        'SY1PEPF000066C2.mail.protection.outlook.com (10.167.241.52) with Microsoft SMTP Server; '
        'Thu, 4 Jun 2026 00:41:23 +0000'
        'X-ExclaimerHostedSignatures-MessageProcessed: true'
        'X-ExclaimerProxyLatency: 31187596'
        'From: Sender &lt;sender@sender.example&gt;'
        'To: Recipient &lt;recipient@example.net&gt;'
        'Subject: Reminder of workplace communication'
        'Thread-Topic: Reminder of workplace communication'
        'Message-ID: &lt;example-message-id@example.net&gt;'
        '</div></div>'
    )

    response = client.post(
        '/api/v1/analyze?fields=spf,dkim,dmarc,source_ip,hops,subject,direction',
        json={'headers': halo_headers},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['results']['spf_verdict'] == 'pass'
    assert payload['results']['dkim_verdict'] == 'none'
    assert payload['results']['dmarc_verdict'] == 'pass'
    assert payload['results']['source_ip'] == '13.70.157.244'
    assert payload['results']['hop_count'] == 3
    assert payload['results']['subject'] == 'Reminder of workplace communication'

    normalized = _sanitize_header_input(halo_headers)
    assert normalized.startswith('Received:')
    assert '<div' not in normalized
    assert '&lt;' not in normalized
    assert 'Sender <sender@sender.example>' in normalized
    assert '\nAuthentication-Results:' in normalized


def test_analyze_api_logs_request_diagnostics_when_enabled(monkeypatch, caplog):
    monkeypatch.setenv('HEADERHORNET_LOG_API_REQUESTS', '1')
    monkeypatch.setenv('HEADERHORNET_LOG_API_REQUEST_BODY', '1')
    client = app.test_client()

    with caplog.at_level(logging.INFO, logger='mha.server'):
        response = client.post(
            '/api/v1/analyze?fields=spf,source_ip',
            json={'headers': SAMPLE_HEADERS},
            headers={'X-API-Key': 'should-not-be-logged'},
        )

    assert response.status_code == 200
    log_output = '\n'.join(record.getMessage() for record in caplog.records)
    assert 'HeaderHornet API request diagnostics' in log_output
    assert 'query_string=fields=spf,source_ip' in log_output
    assert 'content_type=application/json' in log_output
    assert 'raw_body=' in log_output
    assert 'normalized_headers=' in log_output
    assert 'Authentication-Results:' in log_output
    assert 'should-not-be-logged' not in log_output


def test_analyze_api_rejects_missing_headers():
    client = app.test_client()

    response = client.post('/api/v1/analyze', json={})

    assert response.status_code == 400
    payload = response.get_json()
    assert payload['ok'] is False
    assert 'headers' in payload['error']['message']


def test_analyze_api_allows_requests_without_api_key_when_auth_not_configured(monkeypatch):
    monkeypatch.delenv('HEADERHORNET_API_KEY', raising=False)
    client = app.test_client()

    response = client.post('/api/v1/analyze', json={'headers': SAMPLE_HEADERS})

    assert response.status_code == 200
    assert response.get_json()['ok'] is True


def test_analyze_api_rejects_missing_api_key_when_auth_configured(monkeypatch):
    monkeypatch.setenv('HEADERHORNET_API_KEY', 'secret-test-key')
    client = app.test_client()

    response = client.post('/api/v1/analyze', json={'headers': SAMPLE_HEADERS})

    assert response.status_code == 401
    payload = response.get_json()
    assert payload['ok'] is False
    assert payload['error']['code'] == 'unauthorized'
    assert 'API key' in payload['error']['message']


def test_text_plain_analyze_api_rejects_missing_api_key_when_auth_configured(monkeypatch):
    monkeypatch.setenv('HEADERHORNET_API_KEY', 'secret-test-key')
    client = app.test_client()

    response = client.post(
        '/api/v1/analyze',
        data=SAMPLE_HEADERS,
        content_type='text/plain',
    )

    assert response.status_code == 401
    payload = response.get_json()
    assert payload['ok'] is False
    assert payload['error']['code'] == 'unauthorized'


def test_analyze_api_accepts_x_api_key_header(monkeypatch):
    monkeypatch.setenv('HEADERHORNET_API_KEY', 'secret-test-key')
    client = app.test_client()

    response = client.post(
        '/api/v1/analyze',
        json={'headers': SAMPLE_HEADERS},
        headers={'X-API-Key': 'secret-test-key'},
    )

    assert response.status_code == 200
    assert response.get_json()['ok'] is True


def test_analyze_api_accepts_bearer_token(monkeypatch):
    monkeypatch.setenv('HEADERHORNET_API_KEY', 'secret-test-key')
    client = app.test_client()

    response = client.post(
        '/api/v1/analyze',
        json={'headers': SAMPLE_HEADERS},
        headers={'Authorization': 'Bearer secret-test-key'},
    )

    assert response.status_code == 200
    assert response.get_json()['ok'] is True


def test_health_api_reports_service_without_api_key(monkeypatch):
    monkeypatch.setenv('HEADERHORNET_API_KEY', 'secret-test-key')
    client = app.test_client()

    response = client.get('/api/v1/health')

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['ok'] is True
    assert payload['service'] == 'headerhornet'


def test_browser_report_includes_mxtoolbox_style_sections(monkeypatch):
    monkeypatch.delenv('HEADERHORNET_API_KEY', raising=False)
    client = app.test_client()

    response = client.post('/', data={'headers': SAMPLE_HEADERS})

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert 'Delivery Information' in page
    assert 'Relay Information' in page
    assert 'SPF and DKIM Information' in page
    assert 'DMARC Compliant' in page
    assert 'Blacklist' in page
