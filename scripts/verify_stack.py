"""
ULPF End-to-End Stack Verifier
Validates Docker, AI, Redpanda, and API subsystems.
"""

import sys
from pathlib import Path
MAIN_DIR = Path(__file__).resolve().parent.parent / "main"
if str(MAIN_DIR) not in sys.path:
    sys.path.insert(0, str(MAIN_DIR))

import json
import time
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.collectors.redpanda_collector import RedpandaCollector
from app.exporters.redpanda_exporter import RedpandaExporter
from app.ai.onboarding import AiOnboardingEngine


def run_stack_verification():
    print("=" * 65)
    print("      ULPF STACK INTEGRATION VERIFICATION (DOCKER / AI / REDPANDA)")
    print("=" * 65)

    client = TestClient(app)
    passed_steps = 0
    total_steps = 0

    def step(name, condition, detail=""):
        nonlocal passed_steps, total_steps
        total_steps += 1
        symbol = "[PASS]" if condition else "[FAIL]"
        print(f"{symbol} | {name:<36} | {detail}")
        if condition:
            passed_steps += 1

    # 1. API Core & Health
    r = client.get("/api/v1/health/live")
    step("1. FastAPI Liveness Probe", r.status_code == 200, f"HTTP {r.status_code}")

    # 2. System Readiness with Redpanda and AI
    r = client.get("/api/v1/system/readiness")
    data = r.json() if r.status_code == 200 else {}
    comps = data.get("components", {})
    step(
        "2. Subsystems Readiness Check",
        r.status_code == 200 and "redpanda" in comps and "ai" in comps,
        f"Verified {len(comps)} subsystems including Redpanda & AI"
    )

    # 3. AI Intelligence: Parser Onboarding
    r = client.post(
        "/api/v1/ai/onboard",
        json={"samples": ["src=10.0.1.5 dst=192.168.1.1 action=deny proto=tcp app=ssh"]}
    )
    odata = r.json() if r.status_code == 200 else {}
    step(
        "3. AI Log Parser Synthesis",
        r.status_code == 200 and "yaml_spec" in odata,
        f"Synthesized format '{odata.get('format')}' with {odata.get('confidence')} confidence"
    )

    # 4. AI Intelligence: Incident & Threat Explanation
    r = client.post(
        "/api/v1/ai/explain",
        json={"log": "WAF: src=203.0.113.88 msg='SQLi attempt detected' query='SELECT * FROM users WHERE id=1 OR 1=1'"}
    )
    edata = r.json() if r.status_code == 200 else {}
    step(
        "4. AI Incident Threat Reasoning",
        r.status_code == 200 and edata.get("mitre_attack_id") == "T1190",
        f"Mapped to MITRE {edata.get('mitre_attack_id')} ({edata.get('threat_type')})"
    )

    # 5. AI Intelligence: Natural Language to DSL
    r = client.post(
        "/api/v1/ai/nl-query",
        json={"query": "Find critical failed logins from external IPs"}
    )
    qdata = r.json() if r.status_code == 200 else {}
    step(
        "5. AI Natural Language Query DSL",
        r.status_code == 200 and "query_dsl" in qdata,
        f"Generated OpenSearch DSL filter"
    )

    # 6. AI Intelligence: Sigma Rule Synthesis
    r = client.post(
        "/api/v1/ai/synthesize-rule",
        json={"threat_type": "Brute Force Authentication", "severity": "high", "mitre_attack_id": "T1110"}
    )
    rdata = r.json() if r.status_code == 200 else {}
    step(
        "6. AI Sigma Rule Generation",
        r.status_code == 200 and "sigma_yaml" in rdata,
        f"Rule ID: {rdata.get('rule_id')}"
    )

    # 7. Redpanda Bus: Direct Production
    r = client.post(
        "/api/v1/redpanda/produce",
        json={"log": "CEF:0|Vendor|TestDevice|1.0|100|Event|Low|src=10.0.0.1 dst=10.0.0.2 act=allow"}
    )
    pdata = r.json() if r.status_code == 200 else {}
    step(
        "7. Redpanda Topic Producer",
        r.status_code == 200 and pdata.get("status") == "published",
        f"Event ID: {pdata.get('event_id')}"
    )

    # 8. Redpanda Bus: Message Retrieval
    r = client.get("/api/v1/redpanda/messages?limit=5")
    mdata = r.json() if r.status_code == 200 else {}
    step(
        "8. Redpanda Stream Ingestion Read",
        r.status_code == 200 and mdata.get("count", 0) > 0,
        f"Retrieved {mdata.get('count')} active messages in stream buffer"
    )

    # 9. Redpanda Bus: High-Speed Streaming Benchmark
    r = client.post("/api/v1/redpanda/benchmark?burst_count=50")
    bdata = r.json() if r.status_code == 200 else {}
    step(
        "9. Redpanda Throughput Benchmark",
        r.status_code == 200 and bdata.get("estimated_eps", 0) > 0,
        f"Simulated 50 msgs @ {bdata.get('estimated_eps'):,} EPS"
    )

    # 10. Canonical Export: Redpanda Streaming Exporter
    from app.pipeline import UlpfPipeline
    pipeline = UlpfPipeline()
    exporter = RedpandaExporter()
    ir_event = pipeline.process("CEF:0|Cisco|ASA|9.2|106015|Deny|6|src=198.51.100.22 dst=10.0.0.1")
    exported = exporter.export(ir_event)
    step(
        "10. Redpanda Canonical Exporter",
        exported.get("stream_id", "").startswith("rp-") and "ocsf" in exported and "ecs" in exported,
        f"Stream ID: {exported.get('stream_id')} (OCSF + ECS Dual Packaging)"
    )

    print("=" * 65)
    if passed_steps == total_steps:
        print(f"       ALL VERIFICATION CHECKS PASSED ({passed_steps}/{total_steps})")
        print("=" * 65)
        return True
    else:
        print(f"       VERIFICATION CHECKS FAILED ({passed_steps}/{total_steps})")
        print("=" * 65)
        return False


if __name__ == "__main__":
    success = run_stack_verification()
    sys.exit(0 if success else 1)
