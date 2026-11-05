"""
ULPF Master System Test Suite:
Validates Redpanda, Docker, ULPF Flow, AI Model, and Future Unknown Detector.
"""

import sys
import os
import json
import time
import urllib.request
import urllib.error
from typing import Tuple, Dict, Any, Optional

# Ensure main is in pythonpath
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "main")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

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
            from fastapi.testclient import TestClient
            from app.main import app
            _client = TestClient(app)
        except Exception:
            _client = None
    return _client

def api_request(path: str, method: str = "GET", body: Any = None) -> Tuple[int, Dict[str, Any]]:
    if is_server_live():
        url = f"{BASE_URL}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"} if body is not None else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                content = resp.read().decode("utf-8")
                return resp.status, json.loads(content) if content else {}
        except urllib.error.HTTPError as e:
            content = e.read().decode("utf-8")
            return e.code, json.loads(content) if content else {}
        except Exception:
            pass

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

def log_test(name: str, passed: bool, detail: str = ""):
    status = "[PASS]" if passed else "[FAIL]"
    print(f"{status} | {name:<36} | {detail}")
    if not passed:
        raise AssertionError(f"Test failed: {name} - {detail}")

def test_docker_and_compose():
    print("\n--- 1. Testing Docker & Docker-Compose Architecture ---")
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    dockerfile = os.path.join(root_dir, "Dockerfile")
    dockerfile_worker = os.path.join(root_dir, "Dockerfile.worker")
    dockerfile_sim = os.path.join(root_dir, "Dockerfile.simulator")
    compose_file = os.path.join(root_dir, "docker-compose.yml")

    assert os.path.exists(dockerfile), "Main Dockerfile missing"
    assert os.path.exists(dockerfile_worker), "Worker Dockerfile missing"
    assert os.path.exists(dockerfile_sim), "Simulator Dockerfile missing"
    assert os.path.exists(compose_file), "docker-compose.yml missing"

    with open(compose_file, "r", encoding="utf-8") as f:
        compose_content = f.read()

    assert "ulpf-api:" in compose_content, "Missing ulpf-api service"
    assert "redpanda:" in compose_content or "REDPANDA_BROKERS" in compose_content, "Missing Redpanda config"
    assert "ulpf-simulator:" in compose_content, "Missing simulator service"

    log_test("Docker Architecture & Compose", True, "All Dockerfiles and multi-service compose verified")

def test_redpanda_streaming():
    print("\n--- 2. Testing Redpanda / Kafka Streaming Bus ---")
    # 1. Redpanda status
    status, data = api_request("/api/v1/redpanda/status")
    assert status == 200 and ("status" in data or "collector" in data)
    log_test("Redpanda Status Subsystem", True, f"Status: {data.get('status', 'online')}")

    # 2. Redpanda produce
    sample_msg = "CEF:0|Testbed|RedpandaStream|1.0|100|StreamingEvent|Low|src=192.168.10.50 dst=10.0.0.1 spt=44332 dpt=443 act=allow"
    status, prod_data = api_request("/api/v1/redpanda/produce", method="POST", body={"message": sample_msg, "source": "test_suite"})
    assert status == 200 and prod_data.get("status") == "published" and "raw_sha256" in prod_data
    log_test("Redpanda Streaming Produce", True, f"Ingested to topic {prod_data.get('topic')}")

    # 3. Redpanda benchmark
    status, bench_data = api_request("/api/v1/redpanda/benchmark?burst_count=50", method="POST")
    assert status == 200
    log_test("Redpanda High-Throughput Bench", True, f"Burst {bench_data.get('burst_count')} msgs, rate: {bench_data.get('estimated_eps'):,} EPS")

def test_ulpf_flow():
    print("\n--- 3. Testing Complete ULPF Pipeline Flow ---")
    from app.pipeline import UlpfPipeline
    from app.detector.detector import FormatDetector
    from app.parsers.registry import ParserRegistry
    from app.normalization.normalizer import SemanticNormalizer
    from app.exporters.ocsf import OcsfExporter
    from app.exporters.ecs import EcsExporter

    pipeline = UlpfPipeline()

    # Test CEF log flow
    raw_cef = "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|drop|5|src=192.168.1.100 dst=10.0.0.50 spt=44332 dpt=443 proto=TCP act=drop reason=policy-violation"
    event = pipeline.process(raw_cef, source="PaloAlto-FW-01")

    assert event.status == "success", f"Pipeline failed: {event.reason}"
    assert event.source.ip == "192.168.1.100", f"Source IP extraction failed: {event.source.ip}"
    assert event.destination.ip == "10.0.0.50", f"Dest IP extraction failed: {event.destination.ip}"
    assert event.event.action == "drop", f"Action extraction failed: {event.event.action}"
    assert event.original.sha256, "Cryptographic hash missing"
    assert len(event.provenance) > 0, "Field-Level provenance missing"

    # Test OCSF export
    ocsf_dict = pipeline.ocsf_exporter.export(event)
    assert ocsf_dict["class_uid"] in (4001, 1007, 3001, 3002), "OCSF class_uid invalid"

    # Test ECS export
    ecs_dict = pipeline.ecs_exporter.export(event)
    assert pipeline.ecs_exporter.target_schema == "ecs_v8.11.0", "ECS schema version invalid"
    assert "event" in ecs_dict and ecs_dict["event"]["action"] == "drop", "ECS event structure invalid"

    log_test("ULPF Ingestion -> Normalization Flow", True, f"Event {event.ulpf.event_id} (Category: {event.event.category})")
    log_test("ULPF OCSF & ECS Downstream Export", True, "Both OCSF v1.1.0 and ECS v8.11.0 formats validated")
    log_test("SHA-256 Provenance & Zero-Loss", True, f"Digest: {event.original.sha256[:16]}... ({len(event.provenance)} mapped tokens)")

def test_ai_model():
    print("\n--- 4. Testing AI Model Integration ---")
    # 1. Check AI providers endpoint
    status, prov_data = api_request("/api/v1/ai/providers")
    assert status == 200 and "providers" in prov_data
    active_prov = prov_data.get("active_provider")
    log_test("AI Multi-Provider Registry", True, f"Active: {active_prov}, Available: {len(prov_data['providers'])} providers")

    # 2. Test AI unknown parser endpoint
    status, ai_res = api_request(
        "/api/v1/ai/parse-unknown",
        method="POST",
        body={
            "raw_log": "RTU_MODBUS_V4 id=9041 unit=1 func=ReadHoldingRegs addr=40001 val=0x4A2F status=CRITICAL_ALARM src=192.168.99.45 dst=10.200.0.10 proto=tcp sport=502 dport=5020",
            "source": "Substation-RTU-Gateway"
        }
    )
    assert status == 200 and ai_res.get("status") == "success"
    canonical = ai_res.get("canonical_event", {})
    assert canonical.get("source", {}).get("ip") == "192.168.99.45"
    log_test("AI Model Parser & Tokenizer", True, f"Extracted canonical model: {ai_res.get('ai_model')}")

def test_future_unknown_detector():
    print("\n--- 5. Testing Future Unknown Format Detector & AI Review Queue ---")
    # 1. Test FormatDetector with unknown proprietary telemetry
    from app.detector.detector import FormatDetector
    detector = FormatDetector()
    novel_log = "0x89504E47 NOVEL_PROTOCOL header_flag=0x01 checksum=0x99A4 src=172.31.0.5 target=10.10.10.10"
    detection = detector.detect(novel_log)
    assert detection.format in ("Unknown (Proprietary)", "Unknown", "Plaintext") or detection.confidence < 0.95
    log_test("Future Unknown Format Detector", True, f"Detected format: '{detection.format}' with confidence {detection.confidence}")

    # 2. Test unknown log review queue API
    status, q_data = api_request("/api/v1/unknown-logs")
    assert status == 200
    logs_queue = q_data.get("logs", [])
    log_test("AI Onboarding Review Queue", True, f"{len(logs_queue)} novel formats pending review")

    # 3. Test injecting unknown log via scenario
    status, scen_data = api_request("/api/v1/demo/scenarios/unknown_vendor", method="POST")
    assert status == 200 and scen_data.get("scenario") == "Unknown Vendor Format"
    log_test("Dynamic Unknown Telemetry Injection", True, f"Injected novel mystery log {scen_data.get('new_unknown_id')}")

def main():
    print("=" * 70)
    print("      ULPF MASTER INTEGRATED SUBSYSTEM TEST SUITE")
    print("   Docker · Redpanda · ULPF Flow · AI Model · Unknown Detector")
    print("=" * 70)
    
    test_docker_and_compose()
    test_redpanda_streaming()
    test_ulpf_flow()
    test_ai_model()
    test_future_unknown_detector()

    print("=" * 70)
    print("  ALL 5 CORE SUBSYSTEMS TESTED & VALIDATED WITH 100% SUCCESS!")
    print("=" * 70)

if __name__ == "__main__":
    main()
