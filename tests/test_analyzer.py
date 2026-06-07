from mha.analyzer import analyze_headers, human_duration


SAMPLE_HEADERS = """Received: from mail.example.net (mail.example.net [203.0.113.10])
        by mx.google.com with ESMTPS id abc123
        for <victim@example.com>;
        Tue, 04 Jun 2024 10:05:00 -0000
Received: from workstation.local (unknown [198.51.100.44])
        by mail.example.net with ESMTP id def456;
        Tue, 04 Jun 2024 10:00:30 -0000
Authentication-Results: mx.google.com;
       spf=pass smtp.mailfrom=sender.example;
       dkim=pass header.d=sender.example;
       dmarc=pass (p=reject sp=reject dis=none) header.from=sender.example
Received-SPF: pass (google.com: domain of sender@example.com designates 203.0.113.10 as permitted sender)
DKIM-Signature: v=1; a=rsa-sha256; d=sender.example; s=selector1;
From: Sender <sender@sender.example>
To: Victim <victim@example.com>
Subject: Test message
Message-ID: <abc123@sender.example>
Date: Tue, 04 Jun 2024 10:00:00 -0000
"""


def test_analyze_headers_returns_summary_route_direction_and_security():
    result = analyze_headers(SAMPLE_HEADERS)

    assert result["summary"]["from"] == "Sender <sender@sender.example>"
    assert result["summary"]["to"] == "Victim <victim@example.com>"
    assert result["summary"]["subject"] == "Test message"
    assert result["direction"]["hop_count"] == 2
    assert result["direction"]["origin"]["host"] == "workstation.local"
    assert result["direction"]["destination"]["host"] == "mx.google.com"
    assert result["direction"]["suspected_source_ip"] == "198.51.100.44"
    assert result["route"][0]["hop"] == 1
    assert result["route"][0]["from"]["host"] == "workstation.local"
    assert result["route"][1]["by"]["host"] == "mx.google.com"
    assert result["timing"]["total_delay_seconds"] == 270
    assert result["security"]["spf"]["verdict"] == "pass"
    assert result["security"]["dkim"]["verdict"] == "pass"
    assert result["security"]["dmarc"]["verdict"] == "pass"


def test_human_duration_formats_zero_and_multi_unit_values():
    assert human_duration(0) == "0 sec"
    assert human_duration(3661) == "1 hr, 1 min, 1 sec"
