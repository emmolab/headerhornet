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


SQUASHED_HEADERS_FROM_SOAR_BODY = (
    "Received: from SY8PR01MB9220.ausprd01.prod.outlook.com (::1) by "
    "SY7PR01MB9171.ausprd01.prod.outlook.com with HTTPS; Thu, 4 Jun 2026 00:41:35 +0000"
    "Received: from SY5PR01CA0112.ausprd01.prod.outlook.com (2603:10c6:10:246::11) by "
    "SY8PR01MB9220.ausprd01.prod.outlook.com (2603:10c6:10:22f::13) with Microsoft SMTP Server; Thu, 4 Jun 2026 00:41:25 +0000"
    "Authentication-Results: spf=pass (sender IP is 13.70.157.244) smtp.mailfrom=sender.example; "
    "dkim=none (message not signed) header.d=none;dmarc=pass action=none header.from=sender.example;"
    "Received-SPF: Pass (protection.outlook.com: domain of sender.example designates 13.70.157.244 as permitted sender) "
    "receiver=protection.outlook.com; client-ip=13.70.157.244; helo=au2.smtp.exclaimer.net; pr=C"
    "Received: from au2.smtp.exclaimer.net (13.70.157.244) by SY1PEPF000066C2.mail.protection.outlook.com "
    "(10.167.241.52) with Microsoft SMTP Server; Thu, 4 Jun 2026 00:41:23 +0000"
    "X-ExclaimerHostedSignatures-MessageProcessed: true"
    "X-ExclaimerProxyLatency: 31187596"
    "From: Sender <sender@sender.example>"
    "To: Recipient <recipient@example.com>"
    "Subject: Reminder of workplace communication"
    "Thread-Topic: Reminder of workplace communication"
    "Date: Thu, 4 Jun 2026 00:41:19 +0000"
    "Message-ID:<SYBPR01MB50490ECC7ECB77D1D6D78E3D97102@example.com>"
    "Authentication-Results-Original: dkim=none (message not signed) header.d=none;"
    "dmarc=none action=none header.from=sender.example;"
    "X-Forefront-Antispam-Report: CIP:13.70.157.244;CTRY:AU;LANG:en;SCL:1;DIR:INT;"
)


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


HALO_HEADERS_WITH_INTERNAL_SUBMISSION_BEFORE_EXTERNAL_GATEWAY = """Received: from final.example (::1) by mailbox.example with HTTPS; Thu, 4 Jun 2026 00:41:35 +0000
Received: from mid.example (2603:10c6:10:246::11) by final.example with Microsoft SMTP Server; Thu, 4 Jun 2026 00:41:25 +0000
Authentication-Results: spf=pass (sender IP is 13.70.157.244) smtp.mailfrom=sender.example; dkim=none (message not signed) header.d=none;dmarc=pass action=none header.from=sender.example;
Received-SPF: Pass (protection.outlook.com: domain of sender.example designates 13.70.157.244 as permitted sender) receiver=protection.outlook.com; client-ip=13.70.157.244; helo=au2.smtp.exclaimer.net; pr=C
Received: from au2.smtp.exclaimer.net (13.70.157.244) by protection.example (10.167.241.52) with Microsoft SMTP Server; Thu, 4 Jun 2026 00:41:23 +0000
Received: from outbound.example (40.93.136.29) by au2.smtp.exclaimer.net (13.70.157.244) with Exclaimer Signature Manager ESMTP Proxy; Thu, 4 Jun 2026 00:41:25 +0000
Received: from mailbox-origin.example (2603:10c6:10:12::13) by internal-relay.example with Microsoft SMTP Server; Thu, 4 Jun 2026 00:41:19 +0000
Received: from mailbox-origin.example ([fe80::d0d3:834f:fb9f:a44d]) by mailbox-origin.example with mapi id 15.21.0071.015; Thu, 4 Jun 2026 00:41:19 +0000
From: Sender <sender@sender.example>
Subject: Internal submission before external gateway
X-Forefront-Antispam-Report: CIP:13.70.157.244;CTRY:AU;H:au2.smtp.exclaimer.net;DIR:INT;
"""


def test_source_ip_prefers_spf_authenticated_gateway_over_internal_submission_hops():
    client = app.test_client()

    response = client.post(
        '/api/v1/analyze?fields=spf,dkim,dmarc,source_host,source_ip,hops,direction',
        json={'headers': HALO_HEADERS_WITH_INTERNAL_SUBMISSION_BEFORE_EXTERNAL_GATEWAY},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['results']['spf_verdict'] == 'pass'
    assert payload['results']['dkim_verdict'] == 'none'
    assert payload['results']['dmarc_verdict'] == 'pass'
    assert payload['results']['source_ip'] == '13.70.157.244'
    assert payload['results']['source_host'] == 'au2.smtp.exclaimer.net'
    assert payload['results']['hop_count'] == 6


def test_squashed_header_blob_is_rehydrated_before_analysis():
    client = app.test_client()

    response = client.post(
        '/api/v1/analyze?fields=spf,dkim,dmarc,source_host,source_ip,hops,subject',
        json={'headers': SQUASHED_HEADERS_FROM_SOAR_BODY},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['results']['spf_verdict'] == 'pass'
    assert payload['results']['dkim_verdict'] == 'none'
    assert payload['results']['dmarc_verdict'] == 'pass'
    assert payload['results']['source_host'] == 'au2.smtp.exclaimer.net'
    assert payload['results']['source_ip'] == '13.70.157.244'
    assert payload['results']['hop_count'] == 3
    assert payload['results']['subject'] == 'Reminder of workplace communication'
