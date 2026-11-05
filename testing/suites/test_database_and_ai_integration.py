import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.storage.database import DatabaseManager
from app.ai.providers import (
    AiProviderFactory,
    BaseAiModelProvider,
    OllamaProvider,
    OpenAiProvider,
    GeminiProvider,
    AnthropicProvider,
    HuggingFaceProvider,
    LocalMLDetectorProvider,
    HeuristicProvider,
)
from app.ai.onboarding import AiOnboardingEngine


@pytest.fixture
def test_db(tmp_path):
    """Fixture providing isolated temporary SQLite database for tests."""
    db_file = str(tmp_path / "test_integration.db")
    db = DatabaseManager(db_path=db_file, db_type="sqlite")
    return db


@pytest.fixture
def client():
    """FastAPI TestClient fixture."""
    return TestClient(app)


# =============================================================================
# 1. DATABASE INTEGRATION TESTS
# =============================================================================
class TestDatabaseIntegration:
    """Test full multi-backend database capabilities, DAOs, and health probes."""

    def test_database_initialization_and_health(self, test_db):
        health = test_db.check_health()
        assert health["status"] == "healthy"
        assert health["backend"] == "sqlite"
        assert health["persisted"] is True
        assert health["multi_backend_ready"] is True
        assert "events" in health["table_counts"]
        assert "sources" in health["table_counts"]
        assert "parsers" in health["table_counts"]

    def test_event_crud_and_metrics(self, test_db):
        event_record = {
            "event_id": "ULPF-TEST-001",
            "raw_event_id": "RAW-001",
            "timestamp": "2026-09-11T12:00:00Z",
            "source": "Firewall-Edge",
            "vendor": "Cisco",
            "product": "ASA",
            "format": "Syslog",
            "event_type": "network_traffic",
            "action": "deny",
            "severity": "high",
            "src_ip": "198.51.100.25",
            "dst_ip": "10.0.0.1",
            "parser": "syslog",
            "status": "success",
            "sha256": "abc123hash",
            "raw_message": "<163>Sep 11 12:00:00 cisco %ASA-4-106023: Deny tcp src 198.51.100.25 dst 10.0.0.1",
            "threat": {"type": "port_scan", "confidence": 0.95},
        }

        # Save event
        saved = test_db.save_event(event_record)
        assert saved is True

        # Retrieve event
        fetched = test_db.get_event("ULPF-TEST-001")
        assert fetched is not None
        assert fetched["event_id"] == "ULPF-TEST-001"
        assert fetched["src_ip"] == "198.51.100.25"
        assert fetched["action"] == "deny"
        assert fetched["threat"]["type"] == "port_scan"

        # Query events with filters
        total, events = test_db.query_events(severity="high", action="deny")
        assert total >= 1
        assert any(e["event_id"] == "ULPF-TEST-001" for e in events)

        # Metrics summary
        metrics = test_db.get_metrics_summary()
        assert metrics["total_processed"] >= 1
        assert metrics["success_cnt"] >= 1
        assert "Syslog" in metrics["fmt_dist"]

    def test_source_repository(self, test_db):
        src_data = {
            "source_id": "Edge-Router-01",
            "name": "Perimeter Router Alpha",
            "source_type": "Router",
            "vendor": "Juniper",
            "protocol": "Syslog UDP",
            "address": "192.168.1.1",
            "expected_format": "Syslog",
            "status": "ACTIVE",
            "is_blocked": 0,
        }

        # Save source
        saved = test_db.save_source(src_data)
        assert saved is True

        # Get single source
        src = test_db.get_source("Edge-Router-01")
        assert src is not None
        assert src["name"] == "Perimeter Router Alpha"
        assert src["vendor"] == "Juniper"
        assert src["is_blocked"] == 0

        # Update source blocking
        test_db.update_source_status("Edge-Router-01", "BLOCKED", 1)
        src_blocked = test_db.get_source("Edge-Router-01")
        assert src_blocked["status"] == "BLOCKED"
        assert src_blocked["is_blocked"] == 1

        # List sources
        all_sources = test_db.list_sources()
        assert len(all_sources) >= 1
        assert any(s["source_id"] == "Edge-Router-01" for s in all_sources)

        # Delete source
        deleted = test_db.delete_source("Edge-Router-01")
        assert deleted is True
        assert test_db.get_source("Edge-Router-01") is None

    def test_parser_repository(self, test_db):
        parser_data = {
            "parser_id": "custom_iot_gw_v1",
            "name": "Custom IoT Gateway Parser",
            "format": "delimited",
            "version": "1.0",
            "status": "ACTIVE",
            "confidence": 0.95,
            "author": "ULPF Autonomous Studio",
            "description": "Parser for pipeline pipe-delimited telemetry",
            "yaml_spec": "parser:\n  id: custom_iot_gw_v1\n",
        }

        saved = test_db.save_parser(parser_data)
        assert saved is True

        p = test_db.get_parser("custom_iot_gw_v1")
        assert p is not None
        assert p["name"] == "Custom IoT Gateway Parser"
        assert p["confidence"] == 0.95

        all_parsers = test_db.list_parsers()
        assert any(x["parser_id"] == "custom_iot_gw_v1" for x in all_parsers)

        test_db.delete_parser("custom_iot_gw_v1")
        assert test_db.get_parser("custom_iot_gw_v1") is None

    def test_audit_log_and_config(self, test_db):
        # Audit logging
        logged = test_db.record_audit_log(
            action="SOURCE_BLOCKED",
            user_name="soc_analyst",
            detail="Blocked rogue scanner IP 203.0.113.88",
            status="SUCCESS",
        )
        assert logged is True

        audit_entries = test_db.query_audit_logs(limit=10)
        assert len(audit_entries) >= 1
        assert audit_entries[0]["action"] == "SOURCE_BLOCKED"
        assert audit_entries[0]["user_name"] == "soc_analyst"

        # System Config
        test_db.set_config("retention_policy_days", "90")
        test_db.set_config("ai_anomaly_threshold", "0.75")

        val = test_db.get_config("retention_policy_days")
        assert val == "90"

        all_cfg = test_db.list_config()
        assert all_cfg["retention_policy_days"] == "90"
        assert all_cfg["ai_anomaly_threshold"] == "0.75"

    def test_connection_target_tester(self, tmp_path):
        # Test SQLite target tester
        valid_sqlite = f"sqlite:///{tmp_path / 'probe.db'}"
        res = DatabaseManager.test_connection_target(valid_sqlite)
        assert res["status"] == "connected"
        assert res["backend"] == "sqlite"

        # Test invalid scheme
        invalid_res = DatabaseManager.test_connection_target("redis://localhost:6379")
        assert invalid_res["status"] == "unsupported_scheme"


# =============================================================================
# 2. AI MODEL MULTI-PROVIDER & ANOMALY DETECTOR TESTS
# =============================================================================
class TestAiModelIntegration:
    """Test multi-provider AI engine, fallback cascade, and Scikit-Learn anomaly detector."""

    def test_provider_factory_instantiation(self):
        providers = ["ollama", "openai", "gemini", "anthropic", "huggingface", "local_ml", "heuristic"]
        for p_name in providers:
            provider = AiProviderFactory.get_provider(p_name)
            assert isinstance(provider, BaseAiModelProvider)
            assert provider.provider_name == p_name

    def test_local_ml_anomaly_detector(self):
        detector = LocalMLDetectorProvider()
        health = detector.check_health()
        assert health["status"] == "ready"
        assert health["offline_air_gapped"] is True

        # Normal log scoring
        normal_log = "<134>Sep 11 14:00:00 gateway01 system: user admin logged in successfully via ssh"
        normal_score = detector.score_anomaly(normal_log)
        assert normal_score["anomaly_score"] < 0.60
        assert "features" in normal_score
        assert normal_score["features"]["shannon_entropy"] > 0

        # High-threat attack log scoring (SQL Injection)
        attack_log = "WAF_ALERT: src=203.0.113.88 payload=' UNION SELECT password, username FROM admin_users WHERE 1=1 --"
        attack_score = detector.score_anomaly(attack_log)
        assert attack_score["anomaly_score"] >= 0.50
        assert attack_score["severity"] in ("high", "critical")
        assert any("SQL injection" in f for f in attack_score["anomaly_factors"])

    def test_ai_onboarding_engine_capabilities(self):
        engine = AiOnboardingEngine()
        status = engine.get_status()
        assert status["capabilities"] is not None
        assert "multi_provider_llm" in status["capabilities"]
        assert "real_time_ml_scoring" in status["capabilities"]

        # Parser synthesis fallback
        samples = ["DEV=FW-01|TIME=1725619200|SRC=198.51.100.42|DST=10.0.4.15|PORT=8883|EVT=AUTH_FAIL"]
        proposal = engine.analyze_samples(samples)
        assert proposal.format in ("delimited", "key_value")
        assert "yaml_spec" in proposal.model_dump()
        assert proposal.confidence > 0.80

        # Incident explanation fallback
        exp = engine.explain_incident("AUTH_FAIL repeated 50 times from 198.51.100.42 against port 22")
        assert exp.threat_type == "Credential Stuffing / Brute Force"
        assert exp.severity == "high"
        assert exp.mitre_attack_id == "T1110.001"
        assert len(exp.recommended_actions) >= 1

        # Natural language query translation
        trans = engine.nl_to_query("Show all critical failed authentication attempts from 198.51.100.42")
        assert "query" in trans.query_dsl
        assert trans.ulpf_filter.get("event.category") == "authentication"
        assert trans.confidence >= 0.90

        # Sigma rule synthesis
        rule = engine.synthesize_detection_rule({
            "threat_type": "SQL Injection Attack",
            "severity": "critical",
            "mitre_attack_id": "T1190",
            "mitre_attack_name": "Exploit Public-Facing Application",
        })
        assert "SQL Injection Attack" in rule.title
        assert rule.level == "critical"
        assert "attack.t1190" in rule.mitre_tags

        # Real-time log threat scoring
        scored = engine.score_log("DROP inbound TCP packet from scanner 198.51.100.99 to 10.0.0.5:443")
        assert "anomaly_score" in scored
        assert "threat_classification" in scored
        assert "evaluation_engine" in scored

    def test_ai_provider_switching(self):
        engine = AiOnboardingEngine()
        assert engine.switch_provider("local_ml") is True
        assert engine.provider == "local_ml"

        assert engine.switch_provider("heuristic") is True
        assert engine.provider == "heuristic"

        assert engine.switch_provider("invalid_provider_xyz") is False
        assert engine.provider == "heuristic"


# =============================================================================
# 3. REST API ENDPOINTS TESTS
# =============================================================================
class TestApiIntegrationEndpoints:
    """Test newly integrated Database and AI REST API endpoints."""

    def test_database_status_api(self, client):
        resp = client.get("/api/v1/database/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "backend" in data
        assert "table_counts" in data
        assert data["multi_backend_ready"] is True

    def test_database_test_connection_api(self, client, tmp_path):
        target = f"sqlite:///{tmp_path / 'api_test.db'}"
        resp = client.post("/api/v1/database/test-connection", json={"url": target})
        assert resp.status_code == 200
        assert resp.json()["status"] == "connected"

    def test_database_config_api(self, client):
        post_resp = client.post("/api/v1/database/config", json={"key": "api_test_key", "value": "test_val_123"})
        assert post_resp.status_code == 200
        assert post_resp.json()["status"] == "saved"

        get_resp = client.get("/api/v1/database/config")
        assert get_resp.status_code == 200
        assert get_resp.json().get("api_test_key") == "test_val_123"

    def test_ai_providers_list_api(self, client):
        resp = client.get("/api/v1/ai/providers")
        assert resp.status_code == 200
        data = resp.json()
        assert "active_provider" in data
        assert "providers" in data
        provider_names = [p["provider"] for p in data["providers"]]
        assert "ollama" in provider_names
        assert "openai" in provider_names
        assert "gemini" in provider_names
        assert "local_ml" in provider_names

    def test_ai_switch_provider_api(self, client):
        resp = client.post("/api/v1/ai/switch-provider", json={"provider": "local_ml"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "switched"
        assert resp.json()["active_provider"] == "local_ml"

    def test_ai_score_log_api(self, client):
        log_msg = "CEF:0|CheckPoint|VPN-1|R80.40|drop|Drop packet|9|src=198.51.100.77 dst=10.0.1.1 msg=SQLi attempt"
        resp = client.post("/api/v1/ai/score-log", json={"log": log_msg})
        assert resp.status_code == 200
        data = resp.json()
        assert "anomaly_score" in data
        assert "severity" in data
        assert "threat_classification" in data
