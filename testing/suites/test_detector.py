import pytest
from app.detector.format_detector import FormatDetector


def test_format_detector_cef():
    detector = FormatDetector()
    raw = "CEF:0|CheckPoint|VPN-1|R80|100|Accept|Low|src=10.0.0.1 dst=10.0.0.2"
    res = detector.detect(raw)
    assert res.format == "CEF"
    assert res.confidence >= 0.95


def test_format_detector_leef():
    detector = FormatDetector()
    raw = "LEEF:2.0|Imperva|SecureSphere|13.5|HTTP_Violation|src=10.0.0.1"
    res = detector.detect(raw)
    assert res.format == "LEEF"
    assert res.confidence >= 0.95


def test_format_detector_json():
    detector = FormatDetector()
    raw = '{"src_ip": "10.0.0.1", "action": "deny"}'
    res = detector.detect(raw)
    assert res.format == "JSON"
    assert res.confidence == 1.0


def test_format_detector_syslog():
    detector = FormatDetector()
    raw = "<134>Jan 10 14:32:01 server1 firewall: src=10.0.0.1 action=allow"
    res = detector.detect(raw)
    assert res.format == "Syslog"
    assert res.confidence >= 0.90


def test_format_detector_kv():
    detector = FormatDetector()
    raw = "src=10.10.1.5 dst=8.8.8.8 spt=443 dpt=51522 action=deny proto=tcp"
    res = detector.detect(raw)
    assert res.format == "Key=Value"
    assert res.confidence >= 0.70


def test_format_detector_plaintext():
    detector = FormatDetector()
    raw = "This is a random unrecognized plain text log message with no structure."
    res = detector.detect(raw)
    assert res.format == "Plaintext"
    assert res.confidence < 0.50


def test_format_detector_empty():
    detector = FormatDetector()
    res = detector.detect("")
    assert res.format == "Plaintext"
    assert res.confidence == 0.0
