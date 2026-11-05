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
