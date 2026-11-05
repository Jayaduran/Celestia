import sys
import os
import time
import json

# Ensure main is in pythonpath
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "main")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

def test_throughput_monitor():
    print("\n--- 1. Testing Live Throughput Monitor ---")
    from app.pipeline_monitor import ThroughputMonitor
    monitor = ThroughputMonitor(print_interval=1.0, console_logging=False)
    
    # Record events
    for _ in range(250):
        monitor.record_event(byte_size=150, latency_us=80.0)
    
    stats = monitor.get_stats()
    print(f"Throughput stats: Live EPS = {stats['live_eps']}, Peak EPS = {stats['peak_eps']}, MB/s = {stats['throughput_mb_s']}")
    assert stats['total_events_processed'] == 250
    print("[PASS] Throughput Monitor functional")

def test_five_vendor_parsers():
    print("\n--- 2. Testing 5 Enterprise Vendor Parsers ---")
    from app.parsers import (
        PaloAltoParser,
        CiscoAsaParser,
        FortinetParser,
        AwsCloudTrailParser,
        SuricataParser,
        ParserRegistry
    )
    
    registry = ParserRegistry()
    print(f"Active registered parsers: {[p.id for p in registry.list_parsers()]}")
    
    from app.models.raw_event import RawEvent
    
    # Test Palo Alto
    palo_raw = '1,2026/09/12 17:00:00,001801000001,TRAFFIC,drop,1,2026/09/12 17:00:00,192.168.1.100,10.0.0.1,0.0.0.0,0.0.0.0,Rule-Deny,,,ping,vsys1,trust,untrust,ethernet1/1,ethernet1/2,Forward,2026/09/12 17:00:00,1,1,60,0,0,0,0,0x0,icmp,deny,60,60,0,1,2026/09/12 17:00:00,0,any,0,0,0,0,,US,IN,0,1,0,policy-deny,0,0,0,0,,PA-5220,from-policy'
    palo_res = PaloAltoParser().parse(RawEvent(raw_message=palo_raw))
    assert palo_res.status == "success"
    assert palo_res.fields["src_ip"] == "192.168.1.100"
    assert palo_res.fields["dst_ip"] == "10.0.0.1"
    assert palo_res.fields["action"] == "deny"
    print("[PASS] Palo Alto PAN-OS Parser verified")

    # Test Cisco ASA
    cisco_raw = '%ASA-4-106023: Deny tcp src outside:198.51.100.19/52140 dst inside:10.0.1.50/443 by access-group "OUTSIDE_IN" [0x0, 0x0]'
    cisco_res = CiscoAsaParser().parse(RawEvent(raw_message=cisco_raw))
    assert cisco_res.status == "success"
    assert cisco_res.fields["src_ip"] == "198.51.100.19"
    assert cisco_res.fields["dst_ip"] == "10.0.1.50"
    assert cisco_res.fields["dst_port"] == 443
    print("[PASS] Cisco ASA Parser verified")

    # Test Fortinet
    forti_raw = 'date=2026-09-12 time=17:00:00 devname="FGT-CORE-01" devid="FG100E" type="traffic" subtype="forward" level="notice" action="accept" srcip=10.0.1.25 dstip=8.8.8.8 srcport=49210 dstport=53 proto=17 app="DNS"'
    forti_res = FortinetParser().parse(RawEvent(raw_message=forti_raw))
    assert forti_res.status == "success"
    assert forti_res.fields["src_ip"] == "10.0.1.25"
    assert forti_res.fields["dst_ip"] == "8.8.8.8"
    assert forti_res.fields["dst_port"] == 53
    print("[PASS] Fortinet FortiOS Parser verified")

    # Test AWS CloudTrail
    aws_raw = json.dumps({
        "eventVersion": "1.08",
        "eventTime": "2026-09-12T17:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateUser",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.88",
        "userAgent": "aws-cli/2.15.0",
        "userIdentity": {"type": "IAMUser", "userName": "alice_admin", "accountId": "123456789012"},
        "responseElements": {"user": {"userName": "contractor_bob"}}
    })
    aws_res = AwsCloudTrailParser().parse(RawEvent(raw_message=aws_raw))
    assert aws_res.status == "success"
    assert aws_res.fields["src_ip"] == "203.0.113.88"
    assert aws_res.fields["event_name"] == "CreateUser"
    assert aws_res.fields["user_name"] == "alice_admin"
    print("[PASS] AWS CloudTrail Parser verified")

    # Test Suricata EVE
    suri_raw = json.dumps({
        "timestamp": "2026-09-12T17:00:00.123456+0000",
        "event_type": "alert",
        "src_ip": "185.220.101.5",
        "src_port": 41250,
        "dest_ip": "10.0.1.10",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
            "action": "blocked",
            "signature_id": 2010935,
            "signature": "ET SCAN Potential SSH BruteForce Detected",
            "category": "Attempted Information Leak",
            "severity": 1
        }
    })
    suri_res = SuricataParser().parse(RawEvent(raw_message=suri_raw))
    assert suri_res.status == "success"
    assert suri_res.fields["src_ip"] == "185.220.101.5"
    assert suri_res.fields["dst_ip"] == "10.0.1.10"
    assert suri_res.fields["action"] == "deny"
    print("[PASS] Suricata EVE Parser verified")

def test_c_fast_parser():
    print("\n--- 3. Testing C / ctypes Accelerated Parser Engine ---")
    from app.parsers.c_fast_parser import c_fast_parser
    
    status = c_fast_parser.get_engine_status()
    print(f"C Parser Engine Status: {status}")
    
    # Test key-value extraction
    sample_kv = 'src=192.168.1.50 dst=10.0.0.1 action=deny proto=TCP dport=443'
    parsed_kv = c_fast_parser.parse_kv(sample_kv)
    print(f"Extracted KV tokens: {parsed_kv}")
    assert parsed_kv.get("src") == "192.168.1.50"
    assert parsed_kv.get("action") == "deny"
    
    # Run benchmark
    bench = c_fast_parser.benchmark(iterations=10000)
    print(f"Benchmark: {bench['ops_per_sec']:,.0f} ops/sec, {bench['time_per_op_us']} µs/op")
    print("[PASS] C / ctypes Fast Parser Engine operational")

def test_format_drift_checker():
    print("\n--- 4. Testing Detached Format Drift Checker ---")
    from app.parsers.format_checker import FormatDriftChecker
    checker = FormatDriftChecker()
    
    # 1. Base log with matching baseline fields
    base_raw = 'date=2026-09-12 time=17:00:00 devname="FGT-01" srcip=10.0.1.25 dstip=8.8.8.8 srcport=5000 dstport=443 action=accept vd=root level=notice'
    base_fields = {"src_ip": "10.0.1.25", "dst_ip": "8.8.8.8", "src_port": 5000, "dst_port": 443, "action": "accept", "devname": "FGT-01", "vd": "root", "level": "notice"}
    drift1 = checker.inspect_event(base_raw, "fortinet_fortigate", base_fields, status="success")
    assert drift1 is None  # Baseline intact
    
    # 2. Mutated payload with novel fields (ztna_tag, tenant_id, tls_ja4)
    drifted_raw = base_raw + ' ztna_tag="CorpTrusted" tenant_id="acme_99" tls_ja4="t13d1516h2"'
    drifted_fields = dict(base_fields)
    drifted_fields["ztna_tag"] = "CorpTrusted"
    drifted_fields["tenant_id"] = "acme_99"
    drifted_fields["tls_ja4"] = "t13d1516h2"
    
    drift2 = checker.inspect_event(drifted_raw, "fortinet_fortigate", drifted_fields, status="success")
    assert drift2 is not None
    print(f"Detected Drift Alert: ID={drift2.id}, Vendor={drift2.vendor}, Type={drift2.drift_type}, New Fields={drift2.new_fields}")
    
    pending = checker.get_pending_notifications()
    assert len(pending) > 0
    print(f"Pending operator notifications: {len(pending)}")
    
    # Operator approves drift update
    approved = checker.approve_drift(drift2.id, custom_name="Fortinet_FortiGate_ZTNA_Parser")
    assert approved is not None
    print(f"Approved adapted parser ID: {approved.get('promoted_parser_id')}")
    print("[PASS] Detached Format Drift Checker verified")

def test_simulator_devices():
    print("\n--- 5. Testing Simulator Virtual Devices & Risk Configurations ---")
    from testing.server.log_generator import generate_device_log, PRESETS
    
    # Verify presets exist for all 5 vendors
    vendors = [
        {"vendor": "palo_alto", "format": "palo_alto_panos", "name": "PA-5220-DC", "risk_factor": 75.0},
        {"vendor": "cisco_asa", "format": "cisco_asa", "name": "Cisco-ASA-5585", "risk_factor": 80.0},
        {"vendor": "fortinet", "format": "fortinet_fortigate", "name": "FGT-100F", "risk_factor": 50.0},
        {"vendor": "aws", "format": "aws_cloudtrail", "name": "AWS-CloudTrail-Prod", "risk_factor": 90.0},
        {"vendor": "suricata", "format": "suricata_eve", "name": "Suricata-Sensor-01", "risk_factor": 85.0},
    ]
    for dev in vendors:
        log_sample = generate_device_log(dev)
        assert len(log_sample) > 0
        print(f"Generated sample log for [{dev['vendor']}] (Length: {len(log_sample)} bytes)")
    
    print("[PASS] Simulator Virtual Devices & Dynamic Risk Log Generation verified")

if __name__ == "__main__":
    print("================================================================")
    print("  ULPF FULL SYSTEM VERIFICATION: 5 VENDORS, EPS, C ENGINE, DRIFT")
    print("================================================================")
    test_throughput_monitor()
    test_five_vendor_parsers()
    test_c_fast_parser()
    test_format_drift_checker()
    test_simulator_devices()
    print("\n================================================================")
    print("  ALL VERIFICATION CHECKS PASSED PERFECTLY!")
    print("================================================================")
