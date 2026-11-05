import hashlib
import pytest
from app.pipeline import UlpfPipeline

# 30 Synthetic Test Events representing network & perimeter security logs
SYNTHETIC_TEST_EVENTS = [
    # 1. Valid CEF
    "CEF:0|CheckPoint|VPN-1|R80.10|1000|Accept Connection|Low|src=10.10.1.5 dst=8.8.8.8 spt=51522 dpt=443 proto=tcp act=allow",
    # 2. CEF with Palo Alto Firewall
    "CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|drop|1|src=192.168.1.50 dst=1.1.1.1 spt=4000 dpt=53 proto=udp act=deny rule=Default-Block",
    # 3. CEF with Cisco ASA
    "CEF:0|Cisco|ASA|9.14|106023|Deny IP|6|src=10.0.0.99 dst=172.16.0.1 spt=1234 dpt=80 proto=tcp act=deny shost=asa5505",
    # 4. Valid LEEF Imperva
    "LEEF:2.0|Imperva|SecureSphere|13.5|HTTP_Violation|^|src=10.2.3.4\tdst=192.168.100.5\tspt=49152\tdpt=80\tproto=tcp\tusr=admin\tact=block",
    # 5. LEEF IBM QRadar
    "LEEF:1.0|IBM|QRadar|7.4|1001|src=172.16.10.5\tdst=8.8.4.4\tspt=5300\tdpt=53\tproto=udp\tact=allow",
    # 6. LEEF Trend Micro
    "LEEF:2.0|Trend Micro|Deep Security|12.0|40001|src=10.50.1.1\tdst=10.50.1.254\tspt=443\tdpt=55432\tproto=tcp\tact=allow",
    # 7. Valid Syslog RFC3164
    "<134>Jan 10 14:32:01 edge-router firewall[1234]: src=172.16.0.50 dst=10.0.0.1 spt=80 dpt=12345 action=drop proto=tcp",
    # 8. Syslog RFC5424
    "<165>1 2026-09-02T12:00:00.000Z fw-host myapp 1234 ID47 [exampleSDID@32473 iut=\"3\"] src=10.0.0.5 dst=10.0.0.10 spt=443 dpt=54321 action=allow proto=tcp",
    # 9. Syslog Fortinet
    "<189>date=2026-09-02 time=12:00:00 devname=\"FG-100E\" srcip=192.168.2.10 dstip=8.8.8.8 srcport=61000 dstport=53 action=\"deny\" proto=17",
    # 10. Malformed Syslog (missing PRI closing bracket)
    "<134Jan 10 14:32:01 server1 src=10.0.0.1 dst=10.0.0.2 action=allow",
    # 11. Malformed Syslog (truncated timestamp)
    "<13>Jan 10 router-1 src=10.1.1.1 dst=10.2.2.2 action=deny",
    # 12. Flat JSON Log
    '{"timestamp": "2026-09-02T12:00:00Z", "source_ip": "10.0.0.55", "source_port": 60000, "dest_ip": "8.8.4.4", "dest_port": 53, "protocol": "udp", "action": "allow", "vendor": "AWS WAF"}',
    # 13. Nested JSON Log
    '{"event": {"type": "firewall_rule", "action": "block"}, "network": {"src_ip": "10.1.2.3", "src_port": 12345, "dst_ip": "192.168.1.1", "dst_port": 22, "protocol": "tcp"}}',
    # 14. Complex Nested JSON Log
    '{"meta": {"vendor": "Cloudflare"}, "connection": {"client": {"ip": "203.0.113.195", "port": 49152}, "server": {"ip": "198.51.100.1", "port": 443}}, "outcome": "deny"}',
    # 15. Key=Value standard
    "src=192.168.1.100 dst=1.1.1.1 spt=54321 dpt=53 action=deny proto=udp rule=\"Block-DNS\" vendor=\"Fortinet\"",
    # 16. Key=Value with quotes & spaces
    'src="10.0.1.5" dst="172.16.5.5" spt=80 dpt=54321 action="accept" policy_name="Allow Web Traffic" user="admin_user"',
    # 17. Key=Value iptables style
    "IN=eth0 OUT=eth1 MAC=00:11:22:33:44:55 SRC=192.168.1.50 DST=8.8.8.8 PROTO=TCP SPT=443 DPT=51522 WINDOW=65535 SYN",
    # 18. Unknown Plaintext string
    "Unparsed kernel alert message from unknown legacy device interface eth0 link down",
    # 19. Plaintext with random numbers
    "SYSTEM WARNING: High temperature detected on core 0 at threshold 85C",
    # 20. Log with missing fields (only src, no dst or port)
    "src=10.0.0.1 action=allow vendor=SonicWall",
    # 21. Log with invalid IP address
    "src=999.888.777.666 dst=8.8.8.8 spt=443 dpt=51522 action=deny proto=tcp",
    # 22. Log with invalid port (out of 0-65535 range)
    "src=10.0.0.1 dst=8.8.8.8 spt=999999 dpt=-50 action=allow proto=tcp",
    # 23. Log with Unicode characters
    "src=10.0.0.1 dst=8.8.8.8 action=deny rule=\"Directiva_Española_Seguridad_\"",
    # 24. Unicode in JSON format
    '{"source_ip": "10.0.0.1", "action": "deny", "user": "Jörgen_Müller_"}',
    # 25. Log with extra whitespace and tabs
    "   src=10.0.0.1   \t  dst=8.8.8.8 \t spt=80  dpt=443   action=allow   ",
    # 26. Empty string
    "",
    # 27. Whitespace-only log
    "   \n\t   ",
    # 28. Very large log string (10 KB payload simulation)
    "CEF:0|Vendor|Product|1.0|100|Test|Low|src=10.0.0.1 dst=8.8.8.8 spt=80 dpt=443 act=allow payload=" + ("A" * 10000),
    # 29. Mixed CEF/KV format
    "CEF:0|CheckPoint|FW|R80|1|Log|Low|src=10.0.0.5 dst=10.0.0.6 spt=100 dpt=200 act=drop extra_kv=val123",
    # 30. Minimal JSON log
    '{"src": "10.0.0.1", "dst": "10.0.0.2"}'
]


@pytest.fixture
def pipeline():
    return UlpfPipeline()


def test_synthetic_events_processing(pipeline):
    """Test all 30 synthetic test events to verify zero unhandled exceptions and full pipeline execution."""
    assert len(SYNTHETIC_TEST_EVENTS) >= 30

    for idx, raw_log in enumerate(SYNTHETIC_TEST_EVENTS, start=1):
        ir = pipeline.process(raw_log)

        # 1. Verification of status
        assert ir.status in ["success", "unparsed"]

        # 2. SHA-256 integrity verification
        expected_hash = hashlib.sha256(raw_log.encode("utf-8")).hexdigest()
        assert ir.original.sha256 == expected_hash
        assert ir.original.message == raw_log

        # 3. Format detection check
        assert any(f in ir.original.format for f in ["CEF", "LEEF", "JSON", "Syslog", "Key=Value", "Plaintext", "AI-Inferred"])

        # 4. Provenance tracking check if parsed successfully
        if ir.status == "success":
            assert isinstance(ir.provenance, dict)
            for canon_key, prov in ir.provenance.items():
                assert prov.original_field is not None
                assert prov.parser is not None
                assert 0.0 <= prov.confidence <= 1.0


def test_sha256_preservation(pipeline):
    log = "src=10.0.0.1 dst=8.8.8.8 action=deny"
    ir = pipeline.process(log)
    computed_sha = hashlib.sha256(log.encode("utf-8")).hexdigest()
    assert ir.original.sha256 == computed_sha
    assert ir.original.message == log


def test_invalid_ip_handling(pipeline):
    log = "src=999.999.999.999 dst=8.8.8.8 action=deny"
    ir = pipeline.process(log)
    assert ir.source.ip == "999.999.999.999"  # Raw string preserved
    assert ir.destination.ip == "8.8.8.8"


def test_invalid_port_handling(pipeline):
    log = "src=10.0.0.1 dst=8.8.8.8 spt=999999 dpt=80 action=allow"
    ir = pipeline.process(log)
    assert ir.source.port is None  # Invalid port rejected/set to None gracefully
    assert ir.destination.port == 80


def test_unicode_log_processing(pipeline):
    log = "src=10.0.0.1 dst=8.8.8.8 action=deny user=Jörgen_Müller_"
    ir = pipeline.process(log)
    assert ir.user.name == "Jörgen_Müller_"
    assert ir.status == "success"


def test_empty_log_processing(pipeline):
    ir = pipeline.process("")
    assert ir.status in ["unparsed", "success"]
    assert ir.original.message == ""
    assert ir.original.sha256 == hashlib.sha256(b"").hexdigest()


def test_very_large_log_processing(pipeline):
    large_payload = "src=10.0.0.1 dst=8.8.8.8 act=deny data=" + ("X" * 100000)
    ir = pipeline.process(large_payload)
    assert ir.status == "success"
    assert ir.source.ip == "10.0.0.1"
    assert ir.original.sha256 == hashlib.sha256(large_payload.encode("utf-8")).hexdigest()
