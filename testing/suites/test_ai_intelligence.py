from app.ai.onboarding import AiOnboardingEngine
from fastapi.testclient import TestClient
from app.main import app


def test_ai_onboarding_engine_synthesis():
    engine = AiOnboardingEngine()
    samples = [
        "src=192.168.1.10 dst=1.1.1.1 spt=5432 dpt=443 act=deny vendor=Fortinet",
        "src=192.168.1.11 dst=1.1.1.1 spt=5433 dpt=443 act=allow vendor=Fortinet",
    ]
    proposal = engine.analyze_samples(samples)
    assert proposal.format in ("key_value", "json", "delimited")
    assert "src" in proposal.detected_fields
    assert proposal.confidence >= 0.80
    assert "parser:" in proposal.yaml_spec


def test_ai_incident_explanation():
    engine = AiOnboardingEngine()

    # 1. SQL Injection sample
    sqli_sample = "WAF-01: CLIENT=203.0.113.88 TARGET=/api/checkout PAYLOAD=' OR 1=1 -- STATUS=403"
    explanation = engine.explain_incident(sqli_sample)
    assert "SQL" in explanation.threat_type
    assert explanation.severity in ("critical", "high")
    assert explanation.mitre_attack_id.startswith("T")
    assert len(explanation.recommended_actions) > 0

    # 2. Brute-force auth fail sample
    auth_sample = "AuthService: user=admin src=198.51.100.99 status=AUTH_FAIL attempts=10"
    explanation2 = engine.explain_incident(auth_sample)
    assert "Brute" in explanation2.threat_type or "Credential" in explanation2.threat_type or "Auth" in explanation2.threat_type or explanation2.severity in ("high", "medium")
    assert explanation2.mitre_attack_id.startswith("T")


def test_ai_nl_to_query():
    engine = AiOnboardingEngine()
    nl_query = "Find all failed logins from 198.51.100.99 in the last hour"
    translation = engine.nl_to_query(nl_query)
    assert "query_dsl" in translation.model_dump()
    assert "ulpf_filter" in translation.model_dump()
    assert translation.confidence > 0.5


def test_ai_synthesize_detection_rule():
    engine = AiOnboardingEngine()
    incident_data = {
        "threat_type": "SQL Injection Attack",
        "severity": "critical",
        "category": "network",
        "mitre_attack_id": "T1190",
        "mitre_attack_name": "Exploit Public-Facing Application"
    }
    rule = engine.synthesize_detection_rule(incident_data)
    assert rule.rule_id.startswith("ulpf_sigma_")
    assert rule.level == "critical"
    assert "title:" in rule.sigma_yaml
    assert "detection:" in rule.sigma_yaml


def test_ai_api_endpoints():
    client = TestClient(app)

    # 1. AI Status
    r = client.get("/api/v1/ai/status")
    assert r.status_code == 200
    sdata = r.json()
    assert "capabilities" in sdata
    assert "fallback_enabled" in sdata

    # 2. AI Onboard
    r = client.post(
        "/api/v1/ai/onboard",
        json={"samples": ["src=10.0.0.1 dst=10.0.0.2 action=allow proto=tcp"]}
    )
    assert r.status_code == 200
    odata = r.json()
    assert "yaml_spec" in odata
    assert odata["confidence"] >= 0.80

    # 3. AI Explain
    r = client.post(
        "/api/v1/ai/explain",
        json={"log": "src=198.51.100.99 user=root status=FAILED_PASSWORD"}
    )
    assert r.status_code == 200
    edata = r.json()
    assert "summary" in edata
    assert "threat_type" in edata
    assert "mitre_attack_id" in edata

    # 4. AI Natural Language Query
    r = client.post(
        "/api/v1/ai/nl-query",
        json={"query": "Show critical firewall drops"}
    )
    assert r.status_code == 200
    qdata = r.json()
    assert "query_dsl" in qdata

    # 5. AI Rule Synthesis
    r = client.post(
        "/api/v1/ai/synthesize-rule",
        json={"threat_type": "Cross-Site Scripting (XSS)", "severity": "high"}
    )
    assert r.status_code == 200
    rdata = r.json()
    assert "sigma_yaml" in rdata
