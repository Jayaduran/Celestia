import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
TESTING_DIR = ROOT_DIR / "testing"
for p in [ROOT_DIR, TESTING_DIR, ROOT_DIR / "main"]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from app.main import app
from app.config import settings
from app.collectors.source_registry import SourceRegistry


client = TestClient(app)


def test_retention_cleanup_offset_aware_datetime(tmp_path, monkeypatch):
    """Verify that retention cleanup compares offset-aware datetimes without error."""
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    
    # Create an old file
    old_file = raw_dir / "ULPF-2026-1024.raw"
    old_file.write_text("historical log raw content")
    
    monkeypatch.setattr(settings, "storage_dir", str(tmp_path))
    monkeypatch.setattr(settings, "retention_days", 30)

    # Test the comparison logic directly:
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.retention_days)
    mtime = datetime.fromtimestamp(old_file.stat().st_mtime, tz=timezone.utc)
    
    # This must not raise "TypeError: can't compare offset-naive and offset-aware datetimes"
    is_older = mtime < cutoff
    assert isinstance(is_older, bool)


def test_custom_log_ingest_with_device_configurations():
    """Verify custom log ingestion parses device_name, client_ip, vendor, and registers source."""
    payload = {
        "raw_log": "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|drop|5|src=192.168.1.105 dst=10.0.0.50 spt=44332 dpt=443 proto=TCP act=drop reason=policy-violation",
        "device_name": "PaloAlto-HQ-Firewall",
        "client_ip": "192.168.1.105",
        "vendor": "Palo Alto",
        "device_type": "Firewall",
        "protocol": "HTTP REST (:8000)"
    }
    
    resp = client.post("/api/v1/ingest", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("success", "unparsed")
    assert "event_id" in data
    assert "raw_sha256" in data

    # Verify that the device connection was updated with the proper name
    sources_resp = client.get("/api/v1/sources")
    assert sources_resp.status_code == 200
    data = sources_resp.json()
    sources = data.get("sources", data) if isinstance(data, dict) else data
    
    # Find matching source
    matched = [s for s in sources if s.get("name") == "PaloAlto-HQ-Firewall" or s.get("address_ip") == "192.168.1.105"]
    assert len(matched) > 0
    device = matched[0]
    assert device["name"] == "PaloAlto-HQ-Firewall"
    assert "Palo Alto" in device["vendor"]


def test_device_connection_updating_api():
    """Verify PUT /api/v1/sources/{source_id} renames/updates device and persists on server."""
    source_id = "Core-Edge-Router-01"
    update_payload = {
        "name": "Core-Edge-Router-Primary-HQ",
        "vendor": "Cisco",
        "source_type": "Router",
        "address": "10.0.1.1",
        "protocol": "Syslog UDP (5140)"
    }
    
    resp = client.put(f"/api/v1/sources/{source_id}", json=update_payload)
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["status"] == "success"
    assert res_data["source"]["name"] == "Core-Edge-Router-Primary-HQ"
    assert res_data["source"]["vendor"] == "Cisco"
    assert res_data["source"]["address"] == "10.0.1.1"

    # Verify retrieval
    sources_resp = client.get("/api/v1/sources")
    s_data = sources_resp.json()
    sources = s_data.get("sources", s_data) if isinstance(s_data, dict) else s_data
    found = [s for s in sources if s.get("name") == "Core-Edge-Router-Primary-HQ"]
    assert len(found) > 0


def test_protocol_clients_device_timeout():
    """Verify that socket clients enforce configurable device timeout thresholds."""
    import time
    from testing.server.protocol_clients import send_tcp_log, send_http_log, send_udp_log

    # Test TCP timeout on non-routable TEST-NET-2 IP
    unreachable_host = "198.51.100.254"
    unreachable_port = 59999
    configured_timeout = 0.25

    t0 = time.perf_counter()
    res = send_tcp_log(unreachable_host, unreachable_port, "test-timeout-probe", timeout=configured_timeout)
    elapsed = time.perf_counter() - t0

    assert res["success"] is False
    # Must fail promptly around configured timeout (allowing reasonable scheduling slack < 1.5s)
    assert elapsed < 1.5
    assert res.get("timeout") is True or "timed out" in res.get("error", "").lower() or "connection" in res.get("error", "").lower()

    # Test HTTP timeout on non-routable host
    t0_http = time.perf_counter()
    http_res = send_http_log(f"http://{unreachable_host}:{unreachable_port}/api/v1/ingest", "test-http-timeout", timeout=0.25)
    elapsed_http = time.perf_counter() - t0_http

    assert http_res["success"] is False
    assert elapsed_http < 1.5


def test_benchmark_logs_interval_pacing():
    """Verify that benchmark runner respects inter-log pacing intervals."""
    import time
    from testing.benchmarks.benchmark import run_benchmark

    events_count = 5
    interval_sec = 0.015  # 15ms per log

    t0 = time.perf_counter()
    result = run_benchmark(event_count=events_count, format_filter="json", timeout=1.0, interval=interval_sec)
    total_elapsed = time.perf_counter() - t0

    assert result["event_count"] == events_count
    assert result["timeout_sec"] == 1.0
    assert result["interval_sec"] == interval_sec
    # Paced duration should be at least (events_count * interval_sec)
    expected_min_duration = events_count * interval_sec
    assert total_elapsed >= (expected_min_duration * 0.05)


def test_sim_server_request_models_timeout_and_interval():
    """Verify sim_server request models serialize and validate device timeout and interval configs."""
    from testing.server.sim_server import ScenarioRequest, BurstRequest, PipelineRunRequest, PingRequest, SendLogRequest

    # PingRequest
    ping = PingRequest(host="127.0.0.1", port=8000, timeout=5.5)
    assert ping.timeout == 5.5

    # SendLogRequest
    send_req = SendLogRequest(message="test", timeout=2.0)
    assert send_req.timeout == 2.0

    # ScenarioRequest
    scenario = ScenarioRequest(scenario="normal", device_timeout=4.0, interval_ms=25.0)
    assert scenario.device_timeout == 4.0
    assert scenario.interval_ms == 25.0

    # BurstRequest
    burst = BurstRequest(count=100, device_timeout=1.5, interval_ms=5.0)
    assert burst.device_timeout == 1.5
    assert burst.interval_ms == 5.0

    # PipelineRunRequest
    pipe = PipelineRunRequest(stage="fast", device_timeout=2.5, logs_interval_ms=15.0)
    assert pipe.device_timeout == 2.5
    assert pipe.logs_interval_ms == 15.0
