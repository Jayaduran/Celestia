import time
from app.collectors.redpanda_collector import RedpandaCollector
from app.exporters.redpanda_exporter import RedpandaExporter
from app.pipeline import UlpfPipeline
from app.models.canonical_event import CanonicalEvent
from app.models.raw_event import create_raw_event
from app.collectors.queue import IngestionQueue
from fastapi.testclient import TestClient
from app.main import app


def test_redpanda_collector_produce_and_consume():
    pipeline = UlpfPipeline()
    consumed_events = []

    def callback(event, source_name=""):
        consumed_events.append(event)

    collector = RedpandaCollector(
        pipeline=pipeline,
        event_callback=callback,
    )
    collector.start()

    try:
        # Produce test log
        test_raw = "CEF:0|CheckPoint|Firewall|R81|100|Accept|Low|src=10.0.1.5 dst=8.8.8.8 spt=443 dpt=53 act=allow"
        res = collector.produce(test_raw, source="test-source")

        assert res["status"] == "published"
        assert res["raw_sha256"] != ""
        assert res["event_id"] is not None

        # Give consumer loop time to pull and process
        for _ in range(20):
            if len(consumed_events) >= 1:
                break
            time.sleep(0.1)

        assert len(consumed_events) >= 1
        first = consumed_events[0]
        assert first.original.sha256 == res["raw_sha256"]

        status = collector.get_status()
        assert status["messages_produced"] >= 1
        assert status["messages_consumed"] >= 1
        assert len(collector.get_recent_messages(limit=5)) >= 1
    finally:
        collector.stop()


def test_redpanda_exporter():
    pipeline = UlpfPipeline()
    exporter = RedpandaExporter()

    raw = "CEF:0|PaloAlto|PAN-OS|10.1|THREAT|vulnerability|9|src=198.51.100.42 dst=10.0.1.15 spt=49152 dpt=445 proto=tcp act=drop"
    ir_event = pipeline.process(raw, source="test-firewall")

    exported = exporter.export(ir_event)
    assert exported["stream_id"].startswith("rp-")
    assert exported["raw_sha256"] == ir_event.original.sha256
    assert "ocsf" in exported
    assert "ecs" in exported
    assert "ulpf_ir" in exported

    metrics = exporter.get_metrics()
    assert metrics["total_exported"] >= 1
    assert metrics["total_bytes_exported"] > 0


def test_redpanda_api_endpoints():
    client = TestClient(app)

    # 1. Status endpoint
    r = client.get("/api/v1/redpanda/status")
    assert r.status_code == 200
    data = r.json()
    assert "collector" in data
    assert "exporter" in data
    assert "queue_metrics" in data

    # 2. Produce endpoint
    r = client.post(
        "/api/v1/redpanda/produce",
        json={"log": "src=10.0.0.1 dst=10.0.0.2 action=allow proto=tcp", "source": "api-test"}
    )
    assert r.status_code == 200
    pdata = r.json()
    assert pdata["status"] == "published"
    assert pdata["raw_sha256"] != ""

    # 3. Messages endpoint
    r = client.get("/api/v1/redpanda/messages?limit=10")
    assert r.status_code == 200
    mdata = r.json()
    assert "messages" in mdata
    assert mdata["count"] >= 1

    # 4. Benchmark endpoint
    r = client.post("/api/v1/redpanda/benchmark?burst_count=20")
    assert r.status_code == 200
    bdata = r.json()
    assert bdata["status"] == "success"
    assert bdata["burst_count"] == 20
    assert bdata["estimated_eps"] > 0
