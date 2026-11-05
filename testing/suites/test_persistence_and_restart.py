import pytest
import tempfile
import hashlib
from pathlib import Path
from app.models.raw_event import create_raw_event
from app.pipeline import UlpfPipeline
from app.storage.database import DatabaseManager
from app.storage.minio_store import MinioStore
from app.storage.persistence import PersistenceManager


def test_sqlite_event_persistence_and_restart():
    """Verify that events written to SQLite persist and can be reloaded after restart."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test_ulpf.db")
        db = DatabaseManager(db_path=db_path)

        # 1. Insert test record
        record = {
            "event_id": "ULPF-2026-TEST-01",
            "raw_event_id": "RAW-01",
            "timestamp": "2026-09-06T12:00:00Z",
            "source": "Firewall-Edge",
            "vendor": "Fortinet",
            "product": "FortiGate",
            "format": "CEF",
            "event_type": "Traffic Blocked",
            "action": "deny",
            "severity": "high",
            "src_ip": "198.51.100.42",
            "dst_ip": "10.0.1.10",
            "parser": "cef",
            "status": "success",
            "sha256": hashlib.sha256(b"raw test log").hexdigest(),
            "raw_message": "raw test log",
            "threat": {"threat_type": "Blocked IP Violation"},
        }

        saved = db.save_event(record, ir_json='{"status": "success"}')
        assert saved is True

        # 2. Query event
        fetched = db.get_event("ULPF-2026-TEST-01")
        assert fetched is not None
        assert fetched["src_ip"] == "198.51.100.42"
        assert fetched["threat"]["threat_type"] == "Blocked IP Violation"

        # 3. Simulate Server Restart (New DB instance on same SQLite file)
        db_restarted = DatabaseManager(db_path=db_path)
        reloaded = db_restarted.get_all_recent_events()
        assert len(reloaded) == 1
        assert reloaded[0]["event_id"] == "ULPF-2026-TEST-01"
        assert reloaded[0]["sha256"] == record["sha256"]


def test_minio_local_fallback_and_integrity_verification():
    """Verify raw evidence storage and cryptographic integrity verification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_dir = Path(tmpdir) / "raw"
        minio_store = MinioStore(local_dir=str(raw_dir))

        raw_payload = "date=2026-09-06 time=12:30:00 devname=FGT-01 action=deny srcip=203.0.113.88 dstip=10.0.0.1"
        expected_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

        # Store raw log (will use local fallback since MinIO is offline in unit test)
        storage_uri, status = minio_store.store_raw_log(
            event_id="EVT-TEST-100",
            raw_message=raw_payload,
            source="Firewall",
            log_format="Key=Value",
            sha256_hash=expected_hash,
        )

        assert "stored" in status
        assert storage_uri is not None

        # Retrieve and verify SHA-256
        content, computed_hash = minio_store.get_raw_log(storage_uri, event_id="EVT-TEST-100")
        assert content == raw_payload
        assert computed_hash == expected_hash
