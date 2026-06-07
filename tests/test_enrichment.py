from mha.analyzer import analyze_headers
from tests.test_analyzer import SAMPLE_HEADERS


def fake_dns_lookup(name, record_type):
    records = {
        ('_dmarc.sender.example', 'TXT'): [
            'v=DMARC1; p=reject; rua=mailto:dmarc@sender.example'
        ],
        ('sender.example', 'TXT'): [
            'v=spf1 ip4:203.0.113.10 -all'
        ],
        ('selector1._domainkey.sender.example', 'TXT'): [
            'v=DKIM1; k=rsa; p=MIIBFAKEKEY'
        ],
    }
    return records.get((name, record_type), [])


def fake_blacklist_lookup(ip):
    return {
        'ip': ip,
        'listed': False,
        'zones': [],
        'status': 'not_listed',
    }


def test_analyze_headers_adds_mxtoolbox_style_validation_sections():
    result = analyze_headers(
        SAMPLE_HEADERS,
        dns_lookup=fake_dns_lookup,
        blacklist_lookup=fake_blacklist_lookup,
    )

    validation = result['validation']
    assert validation['dmarc']['record_found'] is True
    assert validation['dmarc']['policy'] == 'reject'
    assert validation['spf']['record_found'] is True
    assert validation['spf']['source_ip_authorized'] is True
    assert validation['dkim']['selectors'][0]['record_found'] is True
    assert validation['alignment']['spf']['aligned'] is True
    assert validation['alignment']['dkim']['aligned'] is True
    assert validation['dmarc_compliance']['compliant'] is True
    assert validation['dmarc_compliance']['checks']['spf_authenticated'] is True
    assert validation['dmarc_compliance']['checks']['dkim_authenticated'] is True

    assert result['reputation']['checked'] is True
    assert result['reputation']['relay_ips'][0]['status'] == 'not_listed'
    assert result['route'][0]['blacklist']['status'] == 'not_listed'


def test_analyze_headers_reports_missing_dns_validation_records():
    result = analyze_headers(SAMPLE_HEADERS, dns_lookup=lambda name, record_type: [])

    assert result['validation']['dmarc']['record_found'] is False
    assert result['validation']['spf']['record_found'] is False
    assert result['validation']['dkim']['selectors'][0]['record_found'] is False
    assert result['validation']['dmarc_compliance']['compliant'] is False
    assert any('DMARC record' in warning for warning in result['warnings'])
