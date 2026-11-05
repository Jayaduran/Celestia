import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.collectors.syslog_collector import SyslogCollector
from app.collectors.file_collector import FileCollector
from app.exporters.forwarder import LogForwarder, mock_siem
from app.pipeline import UlpfPipeline

client = TestClient(app)


def test_api_ingest_single_log():
    """Test POST /api/v1/ingest with string log."""
    payload = {
        "log": "CEF:0|CheckPoint|VPN-1 & FireWall-1|R80.10|1000|Accept Connection|Low|src=192.168.1.100 dst=8.8.8.8 spt=51522 dpt=443 proto=tcp act=allow shost=fw-edge-01",
        "source": "company-firewall-01"
    }
    response = client.post("/api/v1/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["detected_format"] == "CEF"
    assert data["forwarded"] is True
    assert "raw_sha256" in data
    assert "canonical_event" in data
    assert "ocsf_export" in data
    assert "ecs_export" in data


def test_api_ingest_structured_json():
    """Test POST /api/v1/ingest with structured web application login log."""
    payload = {
        "source": "www.company.com",
        "message": "user=192.168.1.20 action=login_failed url=/login status=401"
    }
    response = client.post("/api/v1/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["forwarded"] is True


def test_api_ingest_batch():
    """Test POST /api/v1/ingest/batch endpoint."""
    batch_payload = {
        "source": "batch_test_server",
        "logs": [
            "CEF:0|CheckPoint|FW|1.0|100|Event|Low|src=10.0.0.1 dst=10.0.0.2 act=allow",
            "LEEF:2.0|Imperva|WAF|1.0|Alert|^\tsrc=172.16.0.1\tdst=10.0.0.5\tact=deny",
            '{"source_ip": "1.1.1.1", "dest_ip": "8.8.8.8", "action": "block"}'
        ]
    }
    response = client.post("/api/v1/ingest/batch", json=batch_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["total_received"] == 3
    assert data["total_processed"] == 3
    assert len(data["events"]) == 3


def test_api_file_upload():
    """Test POST /api/v1/upload file ingestion endpoint."""
    log_content = (
        "CEF:0|CheckPoint|FW|1.0|100|Event|Low|src=10.0.0.1 dst=10.0.0.2 act=allow\n"
        "LEEF:2.0|Imperva|WAF|1.0|Alert|^\tsrc=172.16.0.1\tdst=10.0.0.5\tact=deny\n"
    )
    files = {"file": ("test_upload.log", log_content.encode("utf-8"), "text/plain")}
    response = client.post("/api/v1/upload", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["filename"] == "test_upload.log"
    assert data["lines_processed"] == 2


def test_collectors_status():
    """Test GET /api/v1/collectors endpoint."""
    response = client.get("/api/v1/collectors")
    assert response.status_code == 200
    data = response.json()
    assert "api_collector" in data
    assert "syslog_collector" in data
    assert "file_collector" in data
    assert "downstream_forwarder" in data


def test_mock_siem_forwarder():
    """Test downstream forwarder and GET /api/v1/mock-siem/events endpoint."""
    pipeline = UlpfPipeline()
    forwarder = LogForwarder()

    ir = pipeline.process("src=10.0.0.1 dst=8.8.8.8 action=allow", source="test_fw")
    pkg = forwarder.forward(ir, target_destination="SIEM_DataLake_Sink")

    assert pkg["status"] == "DELIVERED"
    assert pkg["destination"] == "SIEM_DataLake_Sink"

    response = client.get("/api/v1/mock-siem/events")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["count"] > 0


def test_file_collector_ingest():
    """Test FileCollector class direct content ingestion."""
    pipeline = UlpfPipeline()
    fc = FileCollector(pipeline=pipeline)
    events = fc.ingest_file_content("src=10.0.0.5 dst=8.8.8.8 action=deny\n")
    assert len(events) == 1
    assert fc.total_processed == 1
