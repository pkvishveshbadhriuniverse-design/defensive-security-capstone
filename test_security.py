import pytest
from app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_security_headers_and_cookie_flags(client):
    res = client.post("/login", json={"email": "alice@example.local", "password": "TestPass123!"})
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    cookie = res.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=Strict" in cookie

def test_input_validation_blocks_oversized_and_xss_payloads(client):
    client.post("/login", json={"email": "alice@example.local", "password": "TestPass123!"})
    res = client.post("/note", json={"content": "<script>alert(1)</script>"})
    assert res.status_code == 400

def test_debug_mode_disabled():
    assert app.debug is False
