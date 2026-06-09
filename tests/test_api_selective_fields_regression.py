from mha.server import app


MICROSOFT_HEADERS_WITH_ORIGINAL_AUTH = """Received: from SY4PR01MB8168.ausprd01.prod.outlook.com (2603:10c6:10:1::10)
 by SY7PR01MB9828.ausprd01.prod.outlook.com with HTTPS; Tue, 4 Jun 2024 10:05:00 +0000
Authentication-Results-Original: mx.example.com; spf=pass smtp.mailfrom=sender.example; dkim=pass header.d=sender.example; dmarc=pass action=none header.from=sender.example
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass smtp.mailfrom=sender.example; dkim=pass header.d=sender.example; dmarc=pass header.from=sender.example
ARC-Seal: i=1; a=rsa-sha256; d=microsoft.com; s=arcselector9901; cv=pass;
DKIM-Signature: v=1; a=rsa-sha256; d=sender.example; s=selector1;
From: Sender <sender@sender.example>
To: Victim <victim@example.com>
Subject: Microsoft 365 compact field test
Message-ID:<abc123@sender.example>
Date: Tue, 04 Jun 2024 10:00:00 +0000
"""


SUBJECT_WITH_NO_SPACE_NEXT_HEADER = """From: Sender <sender@sender.example>
To: Victim <victim@example.com>
Subject: Only this text
Message-ID:<abc123@sender.example>
Date:Tue, 04 Jun 2024 10:00:00 +0000
Received: from workstation.local (unknown [198.51.100.44]) by mx.example.com;
 Tue, 04 Jun 2024 10:05:00 +0000
"""


def test_compact_response_uses_explicit_flat_result_keys_for_integrations():
    client = app.test_client()

    response = client.post(
        '/api/v1/analyze?fields=spf,dkim,dmarc,arc,dkim_present,source_host,source_ip,hops,blacklist_status,blacklist_listed,reputation_checked,direction',
        json={'headers': MICROSOFT_HEADERS_WITH_ORIGINAL_AUTH},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['ok'] is True
    assert payload['results']['spf_verdict'] == 'pass'
    assert payload['results']['dkim_verdict'] == 'pass'
    assert payload['results']['dmarc_verdict'] == 'pass'
    assert payload['results']['arc_verdict'] == 'pass'
    assert payload['results']['dkim_present'] is True
    assert payload['results']['source_host'] == 'SY4PR01MB8168.ausprd01.prod.outlook.com'
    assert payload['results']['source_ip'] is None
    assert payload['results']['hop_count'] == 1
    assert payload['results']['blacklist_status'] == 'not_checked'
    assert payload['results']['blacklist_listed'] is None
    assert payload['results']['reputation_checked'] is True
    assert 'spf' not in payload['results']
    assert 'hops' not in payload['results']


def test_subject_does_not_capture_following_headers_without_space_after_colon():
    client = app.test_client()

    response = client.post(
        '/api/v1/analyze?fields=subject',
        json={'headers': SUBJECT_WITH_NO_SPACE_NEXT_HEADER},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['results']['subject'] == 'Only this text'
