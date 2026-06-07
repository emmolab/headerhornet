from tests.test_analyzer import SAMPLE_HEADERS
from mha.server import app


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


def test_analyze_api_rejects_missing_headers():
    client = app.test_client()

    response = client.post('/api/v1/analyze', json={})

    assert response.status_code == 400
    payload = response.get_json()
    assert payload['ok'] is False
    assert 'headers' in payload['error']['message']


def test_health_api_reports_service():
    client = app.test_client()

    response = client.get('/api/v1/health')

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['ok'] is True
    assert payload['service'] == 'headerhornet'
