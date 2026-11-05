import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_api_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "phase" in data


def test_api_detect():
    payload = {"log": "CEF:0|CheckPoint|VPN-1|R80|100|Accept|Low|src=10.0.0.1"}
    response = client.post("/detect", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["format"] == "CEF"
    assert data["confidence"] >= 0.95


def test_api_parse():
    payload = {"log": "src=10.10.1.5 dst=8.8.8.8 spt=443 dpt=51522 action=deny proto=tcp"}
    response = client.post("/parse", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["format"] == "Key=Value"
    assert data["extracted_fields"]["src"] == "10.10.1.5"


def test_api_normalize():
    payload = {"log": '{"source_ip": "10.0.0.1", "dest_ip": "8.8.8.8", "action": "deny"}'}
    response = client.post("/normalize", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["normalized_event"]["source"]["ip"] == "10.0.0.1"
    assert data["normalized_event"]["destination"]["ip"] == "8.8.8.8"
    assert data["normalized_event"]["event"]["action"] == "deny"
    assert "source.ip" in data["provenance"]


def test_api_process():
    payload = {"log": "LEEF:1.0|IBM|QRadar|7.4|1001|src=172.16.10.5\tdst=8.8.4.4\tspt=5300\tdpt=53\tproto=udp\tact=allow"}
    response = client.post("/process", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["detection"]["format"] == "LEEF"
    assert data["canonical_event"]["source"]["ip"] == "172.16.10.5"
    assert data["ocsf_export"] is not None
    assert data["ecs_export"] is not None
    assert data["raw_hash"] is not None

