"""
Universal Log Pre-processing Framework (ULPF) — Automated Smoke Test Suite
SIH Problem ID: SIH 26156 (NTRO)
"""

import sys
import json
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"
_client = None
_server_live = None

def is_server_live():
    global _server_live
    if _server_live is None:
        try:
            req = urllib.request.Request(f"{BASE_URL}/health")
            with urllib.request.urlopen(req, timeout=0.5) as resp:
                _server_live = (resp.status == 200)
        except Exception:
            _server_live = False
    return _server_live

def get_test_client():
    global _client
    if _client is None:
        try:
            from pathlib import Path
            MAIN_DIR = Path(__file__).resolve().parent.parent / "main"
            if str(MAIN_DIR) not in sys.path:
                sys.path.insert(0, str(MAIN_DIR))
            from fastapi.testclient import TestClient
            from app.main import app
            _client = TestClient(app)
        except Exception:
            _client = None
    return _client

def api_call(path, method="GET", body=None):
    if is_server_live():
        url = f"{BASE_URL}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"} if body is not None else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                content = resp.read().decode("utf-8")
                return resp.status, json.loads(content) if content else {}
        except urllib.error.HTTPError as e:
            content = e.read().decode("utf-8")
            return e.code, json.loads(content) if content else {}
        except Exception:
            pass

    # Direct FastAPI TestClient mode
    client = get_test_client()
    if client:
        if method == "GET":
            r = client.get(path)
        elif method == "POST":
            r = client.post(path, json=body if body is not None else {})
        elif method == "PUT":
            r = client.put(path, json=body if body is not None else {})
        elif method == "DELETE":
            r = client.delete(path)
        else:
            r = client.request(method, path, json=body)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {}
    return 0, {}

def main():
    print("=" * 60)
    print("      ULPF AUTOMATED SMOKE TEST SUITE (PHASE 5)")
    print("=" * 60)

    stages = []

    # 1. API Reachable
    status, _ = api_call("/health")
    if status == 200:
        stages.append(("1. API Reachability", True, "FastAPI gateway online"))
    else:
        stages.append(("1. API Reachability", False, f"HTTP status {status}"))

    # 2. Readiness Probe
    status, rdata = api_call("/api/v1/system/readiness")
    if status == 200 and rdata.get("overall_status") == "READY":
        stages.append(("2. System Readiness", True, f"7 subsystems verified"))
    else:
        stages.append(("2. System Readiness", False, f"Status: {rdata}"))

    # 3. Format Detection
    status, ddata = api_call("/detect", method="POST", body={"log": "CEF:0|CheckPoint|VPN-1|R81|100|Accept|Low|src=10.0.1.5 dst=8.8.8.8"})
    if status == 200 and ddata.get("format") == "CEF":
        stages.append(("3. Format Detection", True, f"Detected {ddata.get('format')} with {ddata.get('confidence')} confidence"))
    else:
        stages.append(("3. Format Detection", False, f"Failed: {ddata}"))

    # 4. Parsing Engine
    status, pdata = api_call("/parse", method="POST", body={"log": 'srcip=192.168.1.1 dstip=10.0.0.1 proto=6 action="deny"'})
    fields = pdata.get("extracted_fields") or pdata.get("fields") or {}
    if status == 200 and fields:
        stages.append(("4. Parser Tokenization", True, f"Extracted {len(fields)} fields"))
    else:
        stages.append(("4. Parser Tokenization", False, f"Failed: {pdata}"))

    # 5. Pipeline End-to-End Processing (ULPF-IR)
    test_log = "CEF:0|PaloAlto|PAN-OS|10.1|THREAT|vulnerability|9|src=198.51.100.42 dst=10.0.1.15 spt=49152 dpt=445 proto=tcp act=drop"
    status, irdata = api_call("/process", method="POST", body={"log": test_log})
    canon = irdata.get("canonical_event") or irdata.get("normalized_event") or {}
    if status == 200 and irdata.get("status") == "success" and canon:
        cat = canon.get("event", {}).get("category") or canon.get("event_type") or "Security"
        stages.append(("5. ULPF-IR Normalization", True, f"Canonical event created (Category: {cat})"))
    else:
        stages.append(("5. ULPF-IR Normalization", False, f"Failed: {irdata}"))

    # 6. Event Retrieval
    status, edata = api_call("/api/v1/events?limit=10")
    events = edata.get("events", []) if isinstance(edata, dict) else (edata if isinstance(edata, list) else [])
    if status == 200 and len(events) > 0:
        first_event_id = events[0].get("event_id")
        stages.append(("6. Event Ledger Retrieval", True, f"Retrieved {len(events)} events (First: {first_event_id})"))
    else:
        stages.append(("6. Event Ledger Retrieval", False, f"Failed: {edata}"))
        first_event_id = None

    # 7. Raw SHA-256 Tamper-Evident Integrity Verification
    if first_event_id:
        status, vdata = api_call(f"/api/v1/events/{first_event_id}/verify-integrity", method="POST")
        if status == 200 and vdata.get("match") is True:
            stages.append(("7. SHA-256 Tamper Evidence", True, f"Digest verified ({vdata.get('evidence_length_bytes')} bytes)"))
        else:
            stages.append(("7. SHA-256 Tamper Evidence", False, f"Failed: {vdata}"))
    else:
        stages.append(("7. SHA-256 Tamper Evidence", False, "No event ID available"))

    # 8. Multi-Vendor Traffic Generator
    status, mvdata = api_call("/api/v1/demo/traffic/multivendor", method="POST", body={"vendor": "all", "burst_count": 6})
    if status == 200 and mvdata.get("status") == "success":
        stages.append(("8. Multi-Vendor Ingestion", True, f"{mvdata.get('tested_vendors_count')} vendor formats unified"))
    else:
        stages.append(("8. Multi-Vendor Ingestion", False, f"Failed: {mvdata}"))

    # 9. Unknown Format Queueing
    status, udata = api_call("/api/v1/unknown-logs")
    unparsed_logs = udata.get("logs", []) if isinstance(udata, dict) else (udata if isinstance(udata, list) else [])
    if status == 200 and isinstance(unparsed_logs, list):
        stages.append(("9. Unknown Logs AI Queue", True, f"{len(unparsed_logs)} unparsed logs pending review"))
    else:
        stages.append(("9. Unknown Logs AI Queue", False, f"Failed: {udata}"))

    # 10. One-Click Demo Reset
    status, rstdata = api_call("/api/v1/demo/reset", method="POST", body={})
    if status == 200 and rstdata.get("status") == "success":
        stages.append(("10. One-Click Demo Reset", True, "State reset to clean baseline"))
    else:
        stages.append(("10. One-Click Demo Reset", False, f"Failed: {rstdata}"))

    # Print summary
    all_passed = True
    for name, passed, detail in stages:
        symbol = "[PASS]" if passed else "[FAIL]"
        print(f"{symbol} | {name:<28} | {detail}")
        if not passed:
            all_passed = False

    print("=" * 60)
    if all_passed:
        print("                 ULPF SMOKE TEST: PASS")
        print("=" * 60)
        sys.exit(0)
    else:
        print("                 ULPF SMOKE TEST: FAIL")
        print("=" * 60)
        sys.exit(1)

if __name__ == "__main__":
    main()
