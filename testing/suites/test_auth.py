import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_api_auth():
    from app.config import settings
    original_mode = settings.mode
    settings.mode = "PROD"
    settings.api_key = "secret_test_key"

    try:
        # Missing API Key
        res = client.post("/api/v1/events/clear")
        assert res.status_code == 403
        
        # Wrong API Key
        res = client.post("/api/v1/events/clear", headers={"X-API-Key": "wrong_key"})
        assert res.status_code == 403

        # Correct API Key
        res = client.post("/api/v1/events/clear", headers={"X-API-Key": "secret_test_key"})
        assert res.status_code in (200, 204)
        print("Auth test passed!")
    finally:
        settings.mode = original_mode


def test_user_signup_and_login():
    import random
    rand_id = random.randint(10000, 99999)
    username = f"soc_analyst_{rand_id}"
    email = f"analyst_{rand_id}@celestia.sec"
    password = "SecOpsPassword2026!"

    # 1. Register new user
    signup_res = client.post("/api/v1/auth/signup", json={
        "username": username,
        "email": email,
        "password": password,
        "full_name": "Senior SOC Analyst",
        "role": "analyst",
    })
    assert signup_res.status_code == 200
    signup_data = signup_res.json()
    assert signup_data["status"] == "success"
    token = signup_data["token"]
    assert len(token) == 64

    # 2. Check /auth/me with bearer token
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["user"]["username"] == username

    # 3. Authenticate / Login
    login_res = client.post("/api/v1/auth/login", json={
        "username": username,
        "password": password,
    })
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["status"] == "success"
    new_token = login_data["token"]

    # 4. Heartbeat keepalive
    hb_res = client.post("/api/v1/auth/heartbeat", json={"token": new_token, "is_visible": True})
    assert hb_res.status_code == 200
    assert hb_res.json()["active"] is True

    # 5. Presence evaluation should show operator present
    presence_res = client.get("/api/v1/auth/presence")
    assert presence_res.status_code == 200
    pres_data = presence_res.json()
    assert pres_data["operator_present"] is True
    assert pres_data["voice_calls_suppressed"] is True

    # 6. Critical log voice call should be avoided due to active presence
    from app.notifications.twilio_voice import twilio_voice_notifier
    res_call = twilio_voice_notifier.send_voice_call(
        threat_type="Critical RCE Test",
        src_ip="198.51.100.99",
        force=False,
    )
    assert res_call["status"] == "suppressed_presence"
    assert "Voice call avoided" in res_call["message"]

    # 7. Logout session
    logout_res = client.post("/api/v1/auth/logout", json={"token": new_token})
    assert logout_res.status_code == 200

