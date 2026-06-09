from tests.test_analyzer import SAMPLE_HEADERS
from mha.server import app


def test_analyze_api_returns_only_requested_fields_from_query_string():
    client = app.test_client()

    response = client.post(
        '/api/v1/analyze?fields=spf,source_ip,hops,dmarc,dkim,subject,direction',
        json={'headers': SAMPLE_HEADERS},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload == {
        'ok': True,
        'results': {
            'spf_verdict': 'pass',
            'source_ip': '198.51.100.44',
            'hop_count': 2,
            'dmarc_verdict': 'pass',
            'dkim_verdict': 'pass',
            'subject': 'Test message',
            'direction': {
                'origin': {
                    'host': 'workstation.local',
                    'ip': '198.51.100.44',
                },
                'destination': {
                    'host': 'mx.google.com',
                    'ip': None,
                },
            },
        },
    }


def test_analyze_api_returns_requested_fields_from_json_body_aliases():
    client = app.test_client()

    response = client.post(
        '/api/v1/analyze',
        json={
            'headers': SAMPLE_HEADERS,
            'fields': ['SPF', 'Source IP', 'Hop Count', 'DMARC', 'DKIM', 'Subject', 'Message Direction'],
        },
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['ok'] is True
    assert payload['results']['spf_verdict'] == 'pass'
    assert payload['results']['source_ip'] == '198.51.100.44'
    assert payload['results']['hop_count'] == 2
    assert payload['results']['dmarc_verdict'] == 'pass'
    assert payload['results']['dkim_verdict'] == 'pass'
    assert payload['results']['subject'] == 'Test message'
    assert payload['results']['direction']['origin']['host'] == 'workstation.local'
    assert 'analysis' not in payload


def test_analyze_api_rejects_unknown_requested_fields():
    client = app.test_client()

    response = client.post(
        '/api/v1/analyze?fields=spf,not_a_real_field',
        json={'headers': SAMPLE_HEADERS},
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload['ok'] is False
    assert payload['error']['code'] == 'invalid_fields'
    assert 'not_a_real_field' in payload['error']['message']


def test_analyze_api_keeps_full_analysis_when_fields_are_not_requested():
    client = app.test_client()

    response = client.post('/api/v1/analyze', json={'headers': SAMPLE_HEADERS})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['ok'] is True
    assert 'analysis' in payload
    assert 'results' not in payload
