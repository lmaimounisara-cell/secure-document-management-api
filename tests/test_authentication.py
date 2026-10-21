import os
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET", "test-only-jwt-secret-0123456789abcdef")
os.environ.setdefault("WEBHOOK_SECRET", "test-only-webhook-secret-0123456789")
os.environ.setdefault("DEMO_EMPLOYEE_PASSWORD", "TestEmployee-Only-123!")
os.environ.setdefault("DEMO_AUDITOR_PASSWORD", "TestAuditor-Only-123!")
os.environ.setdefault("DEMO_ADMIN_PASSWORD", "TestAdmin-Only-123!")

from server import app

client = TestClient(app)


def test_login_rejects_invalid_password():
    response = client.post(
        "/login",
        json={"username": "alice", "password": "definitely-wrong"},
    )
    assert response.status_code == 401


def test_protected_endpoint_rejects_missing_token():
    response = client.get("/documents")
    assert response.status_code in (401, 403)


def test_invalid_bearer_token_is_rejected():
    response = client.get(
        "/documents",
        headers={"Authorization": "Bearer invalid-token"},
    )
    assert response.status_code == 401
