import pytest
import hashlib
from app.pipeline import UlpfPipeline

@pytest.fixture
def pipeline():
    return UlpfPipeline()

def test_log_injection_prevention(pipeline):
    """Verify that command/SQL injection & script payloads in log lines do not execute and are sanitized/parsed safely."""
    payloads = [
        "src=10.0.0.1 dst=8.8.8.8 action=allow; DROP TABLE events; --",
        "CEF:0|Vendor|Product|1.0|100|<script>alert('XSS')</script>|Low|src=10.0.0.1 dst=8.8.8.8 act=deny",
        '{"source_ip": "10.0.0.1", "user": "admin\' OR \'1\'=\'1", "action": "allow"}',
        "<134>Jan 10 14:32:01 host app: src=10.0.0.1 dst=8.8.8.8 action=$(rm -rf /)",
        "src=10.0.0.1\r\nSET-COOKIE: admin=true\r\n\r\n dst=8.8.8.8 action=deny",
    ]
    for p in payloads:
        ir = pipeline.process(p)
        assert ir.status in ["success", "unparsed"]
        assert ir.original.sha256 == hashlib.sha256(p.encode("utf-8")).hexdigest()

def test_malformed_json_resilience(pipeline):
    """Verify that broken or truncated JSON does not crash the pipeline and falls back cleanly."""
    broken_jsons = [
        '{"source_ip": "10.0.0.1", "dest_ip":',
        '{source_ip: "10.0.0.1", dest_ip: "8.8.8.8"}',
        '{"source_ip": "10.0.0.1", "dest_ip": "8.8.8.8",,,}',
        '{"source_ip": "10.0.0.1" \x00 "dest_ip": "8.8.8.8"}',
    ]
    for bj in broken_jsons:
        ir = pipeline.process(bj)
        assert ir.original.sha256 == hashlib.sha256(bj.encode("utf-8")).hexdigest()

def test_binary_and_null_bytes(pipeline):
    """Verify handling of null bytes and control characters inside log text."""
    null_log = "src=10.0.0.1\x00 dst=8.8.8.8\x01\x02 action=deny"
    ir = pipeline.process(null_log)
    assert ir.original.sha256 == hashlib.sha256(null_log.encode("utf-8", errors="replace")).hexdigest()

def test_repeated_extreme_headers(pipeline):
    """Verify handling of repeated CEF/Syslog headers."""
    repeated = "CEF:0|CheckPoint|FW|1.0|100|Event|Low|" * 50
    ir = pipeline.process(repeated)
    assert ir.original.sha256 == hashlib.sha256(repeated.encode("utf-8")).hexdigest()
