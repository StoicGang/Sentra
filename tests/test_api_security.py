import pytest
from fastapi.testclient import TestClient
from web.api.app import create_app
import os

# Set environment variable for tests
os.environ["SENTRA_ALLOWED_ORIGIN"] = "http://127.0.0.1:7731"

@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)

def test_valid_host_header(client):
    """Verify that requests with valid 127.0.0.1 Host header succeed."""
    response = client.get("/api/openapi.json", headers={"Host": "127.0.0.1:7731"})
    # We expect 200 or 401/403 (if auth required), but NOT 400 Host error
    assert response.status_code != 400

def test_invalid_host_header(client):
    """Verify that requests with invalid Host header are rejected."""
    response = client.get("/api/openapi.json", headers={"Host": "evil.com"})
    assert response.status_code == 400
    assert response.text == "Invalid Host header"

def test_missing_host_header(client):
    """Verify that requests with missing Host header are rejected."""
    # TestClient usually adds a host header, so we explicitly remove it or set empty
    response = client.get("/api/openapi.json", headers={"Host": ""})
    assert response.status_code == 400
    assert response.text == "Invalid Host header"

def test_spoofed_ip_host_header(client):
    """Verify that mismatched IP/Port is rejected."""
    response = client.get("/api/openapi.json", headers={"Host": "127.0.0.1:8080"})
    assert response.status_code == 400
    assert response.text == "Invalid Host header"
