"""
tests/test_network_collectors.py
Comprehensive unit & integration tests for ULPF Network Collectors & Streaming Ingestion.

Tests are aligned to the real implementation APIs:
- RawIngress: connector_type, source, raw_text fields
- SyslogUDPCollector / SyslogTCPCollector: event_callback kwarg
- FileCollector: watch_dir kwarg
- IngestionQueue: max_size, worker_count, get_metrics()
- SourceRegistry: in-memory store, list_sources(), toggle_block(), is_blocked()
- /api/v1/collectors/metrics: status="online", syslog_collector / file_collector / ingestion_queue keys
- /api/v1/ingest: event_id, raw_sha256 in response
"""

import os
import time
import socket
import pytest
import tempfile
import shutil
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.collectors.ingress import RawIngress
from app.collectors.queue import IngestionQueue
from app.collectors.source_registry import SourceRegistry
from app.collectors.syslog_collector import SyslogUDPCollector, SyslogTCPCollector
from app.collectors.file_collector import FileCollector

client = TestClient(app)


# ---------------------------------------------------------------------------
# 1. RawIngress model
# ---------------------------------------------------------------------------

def test_raw_ingress_model():
    """Verify RawIngress auto-generates UUID, computes SHA-256, and exposes convenience properties."""
    payload = '<134>1 2026-09-06T12:00:00Z host app 123 - [meta key="val"] Test log message'
    ingress = RawIngress(
        connector_type="syslog_udp",
        source="192.168.1.100:514",
        raw_text=payload,
        vendor_hint="Cisco",
        product_hint="ASA"
    )
    # UUID auto-generated
    assert ingress.event_id is not None
    assert len(ingress.event_id) == 36
    # SHA-256 auto-calculated
    assert len(ingress.raw_sha256) == 64
    # raw_text preserved verbatim
    assert ingress.raw_text == payload
    # Convenience property aliases
    assert ingress.raw_log == payload
    assert ingress.transport == "syslog_udp"
    assert ingress.source_ip == "192.168.1.100:514"
    assert ingress.vendor_hint == "Cisco"


# ---------------------------------------------------------------------------
# 2. Syslog UDP Collector
# ---------------------------------------------------------------------------

def test_syslog_udp_collector():
    """Test live UDP socket transmission of RFC 3164 and RFC 5424 syslog packets."""
    received: list = []

    def dummy_handler(ingress: RawIngress):
        received.append(ingress)

    port = 25140
    collector = SyslogUDPCollector(host="127.0.0.1", port=port, event_callback=dummy_handler)
    collector.start()
    assert collector.is_running

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # RFC 3164 BSD Syslog
        rfc3164 = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
        sock.sendto(rfc3164, ("127.0.0.1", port))

        # RFC 5424 Structured Syslog
        rfc5424 = b'<165>1 2026-09-06T12:34:56.789Z router.corp BGP 4242 ID47 [origin ip="10.0.0.1"] Peer DOWN'
        sock.sendto(rfc5424, ("127.0.0.1", port))

        # Malformed / binary-safe check (must NOT crash)
        bad = b"<134>\xff\xfe\x00malformed binary packet\x80"
        sock.sendto(bad, ("127.0.0.1", port))

        # Wait up to 2 seconds for the listener thread to dispatch all 3
        deadline = time.time() + 2.0
        while len(received) < 3 and time.time() < deadline:
            time.sleep(0.05)

        assert len(received) == 3
        assert "Oct 11 22:14:15" in received[0].raw_text
        assert received[0].connector_type == "syslog_udp"
        assert "router.corp BGP" in received[1].raw_text
        assert "malformed binary packet" in received[2].raw_text

        status = collector.get_status()
        assert status["is_running"] is True
        assert status["total_received"] >= 3
    finally:
        collector.stop()
        sock.close()


# ---------------------------------------------------------------------------
# 3. Syslog TCP Collector
# ---------------------------------------------------------------------------

def test_syslog_tcp_collector():
    """Test live TCP stream with multi-message and fragmented framing."""
    received: list = []

    def dummy_handler(ingress: RawIngress):
        received.append(ingress)

    port = 25141
    collector = SyslogTCPCollector(host="127.0.0.1", port=port, event_callback=dummy_handler)
    collector.start()
    assert collector.is_running

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))

        # Two newline-delimited messages in a single send
        msg1 = "<134>1 2026-09-06T12:00:01Z fw01 app1 100 - - TCP log line 1\n"
        msg2 = "<134>1 2026-09-06T12:00:02Z fw01 app1 101 - - TCP log line 2\n"
        sock.sendall((msg1 + msg2).encode("utf-8"))

        # Fragmented message across two sends
        part_a = "<134>1 2026-09-06T12:00:03Z fw01 app1 102 - - Fragmen"
        part_b = "ted log line 3\n"
        sock.sendall(part_a.encode("utf-8"))
        time.sleep(0.05)
        sock.sendall(part_b.encode("utf-8"))

        deadline = time.time() + 2.0
        while len(received) < 3 and time.time() < deadline:
            time.sleep(0.05)

        assert len(received) == 3
        assert "TCP log line 1" in received[0].raw_text
        assert "TCP log line 2" in received[1].raw_text
        assert "Fragmented log line 3" in received[2].raw_text
        assert received[0].connector_type == "syslog_tcp"
    finally:
        collector.stop()
        sock.close()


# ---------------------------------------------------------------------------
# 4. File Collector — tailing, offset tracking, rotation detection
# ---------------------------------------------------------------------------

def test_file_collector():
    """Test FileCollector directory scanning, offset tracking, and log rotation."""
    temp_dir = tempfile.mkdtemp(prefix="ulpf_test_file_")
    received: list = []

    def dummy_handler(ingress: RawIngress):
        received.append(ingress)

    collector = FileCollector(watch_dir=temp_dir, event_callback=dummy_handler)

    try:
        test_file = Path(temp_dir) / "app.log"

        # Pre-create an empty file, register it at offset 0, then write content.
        # This mirrors real usage: collector starts watching; device then emits logs.
        test_file.write_text("", encoding="utf-8")
        collector.watch_file(str(test_file.resolve()))
        # Override offset to 0 so all content is treated as new
        collector.watched_files[str(test_file.resolve())]["offset"] = 0

        # 1. Write 2 lines → poll → expect 2 events
        test_file.write_text(
            "2026-09-06 12:00:00 INFO  User login admin\n"
            "2026-09-06 12:00:01 WARN  Failed auth guest\n",
            encoding="utf-8"
        )
        collector.poll_files()
        assert len(received) == 2
        assert "User login admin" in received[0].raw_text
        assert "Failed auth guest" in received[1].raw_text
        assert received[0].connector_type == "file_tail"

        # 2. Append 1 new line → only that line is read
        with open(test_file, "a", encoding="utf-8") as f:
            f.write("2026-09-06 12:00:02 ERROR DB Connection Timeout\n")
        collector.poll_files()
        assert len(received) == 3
        assert "DB Connection Timeout" in received[2].raw_text

        # 3. Simulate log rotation: truncate & rewrite
        test_file.write_text("2026-09-06 12:05:00 INFO  Post-rotation line 1\n", encoding="utf-8")
        collector.poll_files()
        assert len(received) == 4
        assert "Post-rotation line 1" in received[3].raw_text

    finally:
        collector.stop()
        shutil.rmtree(temp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 5. IngestionQueue — worker dispatch and rate limiting
# ---------------------------------------------------------------------------

def test_ingestion_queue_worker_dispatch():
    """Test IngestionQueue processes enqueued events through worker threads."""
    queue = IngestionQueue(
        max_size=100,
        max_eps=1000,      # high limit so all 5 pass rate check
        worker_count=2,
    )
    queue.start()

    try:
        for i in range(5):
            accepted, reason = queue.enqueue(
                RawIngress(connector_type="test", source="test-host", raw_text=f"Queue event {i}")
            )
            assert accepted is True, f"Event {i} rejected with reason: {reason}"

        # Workers consume items; give them up to 2 seconds
        deadline = time.time() + 2.0
        while queue.get_metrics()["total_processed"] < 5 and time.time() < deadline:
            time.sleep(0.05)

        metrics = queue.get_metrics()
        assert metrics["total_enqueued"] == 5
        assert metrics["total_processed"] == 5
        assert metrics["total_dropped_rate_limit"] == 0
    finally:
        queue.stop()


def test_ingestion_queue_rate_limiting():
    """Test IngestionQueue drops events that exceed max_eps limit."""
    queue = IngestionQueue(
        max_size=1000,
        max_eps=3,          # hard cap at 3 events/sec
        worker_count=1,
    )
    queue.start()

    try:
        results = []
        for i in range(10):
            accepted, reason = queue.enqueue(
                RawIngress(connector_type="test", source="test", raw_text=f"Event {i}")
            )
            results.append((accepted, reason))

        accepted_count = sum(1 for a, _ in results if a)
        dropped_count = sum(1 for a, _ in results if not a)

        # With max_eps=3, at most 3 events should be accepted in the first window
        assert accepted_count <= 3
        assert dropped_count >= 7

        metrics = queue.get_metrics()
        assert metrics["total_dropped_rate_limit"] >= 7
    finally:
        queue.stop()

def test_ingestion_queue_per_client_rate_limiting():
    """Test IngestionQueue isolates rate limits per client."""
    queue = IngestionQueue(
        max_size=1000,
        max_eps=3,          # hard cap at 3 events/sec per client
        worker_count=1,
    )
    queue.start()

    try:
        results_client_a = []
        results_client_b = []
        for i in range(10):
            a_acc, _ = queue.enqueue(RawIngress(connector_type="test", source="client_A", raw_text=f"Event {i}"))
            results_client_a.append(a_acc)
            
            if i < 3:
                b_acc, _ = queue.enqueue(RawIngress(connector_type="test", source="client_B", raw_text=f"Event {i}"))
                results_client_b.append(b_acc)

        accepted_a = sum(1 for a in results_client_a if a)
        dropped_a = sum(1 for a in results_client_a if not a)
        
        accepted_b = sum(1 for b in results_client_b if b)
        dropped_b = sum(1 for b in results_client_b if not b)

        # Client A should be capped at 3
        assert accepted_a <= 3
        assert dropped_a >= 7
        
        # Client B only sent 3, should ALL be accepted because it has its own bucket
        assert accepted_b == 3
        assert dropped_b == 0

    finally:
        queue.stop()


# ---------------------------------------------------------------------------
# 6. SourceRegistry — in-memory tracking, block/unblock
# ---------------------------------------------------------------------------

def test_source_registry_register_and_record():
    """Test SourceRegistry source registration, event recording, and list_sources."""
    registry = SourceRegistry()

    # Register two new sources
    registry.register_or_update(
        source_id="test-fw-01",
        name="Test Firewall",
        source_type="Firewall",
        vendor="Cisco",
        protocol="Syslog UDP",
        address="10.0.0.1:5140"
    )
    registry.register_or_update(
        source_id="test-router-01",
        name="Test Router",
        source_type="Router",
        vendor="Juniper",
        protocol="Syslog TCP",
        address="10.0.0.2:5141"
    )

    # Record events for fw-01
    registry.record_event("test-fw-01")
    registry.record_event("test-fw-01")

    sources = registry.list_sources()
    source_ids = [s["id"] for s in sources]
    assert "test-fw-01" in source_ids
    assert "test-router-01" in source_ids

    fw = next(s for s in sources if s["id"] == "test-fw-01")
    assert fw["events_received"] == 2
    assert fw["status"] in ("ACTIVE", "READY")
    assert fw["is_blocked"] is False


def test_source_registry_block_toggle():
    """Test SourceRegistry blocking and unblocking sources."""
    registry = SourceRegistry()
    registry.register_or_update(source_id="test-vpn-01", address="10.0.0.3:5141")

    # Initially not blocked
    assert registry.is_blocked("test-vpn-01") is False

    # First toggle → block
    is_blocked, status = registry.toggle_block("test-vpn-01")
    assert is_blocked is True
    assert registry.is_blocked("test-vpn-01") is True

    # Second toggle → unblock
    is_blocked, status = registry.toggle_block("test-vpn-01")
    assert is_blocked is False
    assert registry.is_blocked("test-vpn-01") is False


# ---------------------------------------------------------------------------
# 7. REST API — /api/v1/collectors/metrics and /api/v1/ingest
# ---------------------------------------------------------------------------

def test_collector_api_metrics():
    """Verify /api/v1/collectors/metrics endpoint returns correct structure."""
    res = client.get("/api/v1/collectors/metrics")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert "syslog_collector" in data
    assert "file_collector" in data
    assert "ingestion_queue" in data


def test_api_ingest_endpoint():
    """Verify POST /api/v1/ingest accepts raw_log with vendor/product hints."""
    payload = {
        "raw_log": "CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Accept|100|src=1.2.3.4 dst=5.6.7.8 proto=tcp",
        "vendor": "CheckPoint",
        "product": "FireWall-1",
    }
    res = client.post("/api/v1/ingest", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "event_id" in data
    assert "raw_sha256" in data
    assert len(data["raw_sha256"]) == 64
    assert data["event_id"] is not None
