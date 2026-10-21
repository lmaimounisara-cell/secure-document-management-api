import hashlib
import hmac
import json
import os
import time
import uuid

os.environ.setdefault("WEBHOOK_SECRET", "test-only-webhook-secret-0123456789")

from fastapi.testclient import TestClient
from audit_server import app

client = TestClient(app)
TEST_SECRET = os.environ["WEBHOOK_SECRET"]


def signed_event(timestamp=None):
    event = {
        "event_id": str(uuid.uuid4()),
        "event": "document_uploaded",
        "user": "test-user",
        "file": "example.txt",
        "sha256": "a" * 64,
        "timestamp": int(time.time()) if timestamp is None else timestamp,
    }
    body = json.dumps(event, separators=(",", ":")).encode()
    signature = hmac.new(
        TEST_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return body, signature


def test_webhook_rejects_missing_signature():
    response = client.post(
        "/webhook",
        content=b'{"event_id":"missing-signature"}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 403


def test_webhook_rejects_invalid_signature():
    response = client.post(
        "/webhook",
        content=b'{"event_id":"invalid-signature"}',
        headers={
            "Content-Type": "application/json",
            "X-Signature": "invalid",
        },
    )
    assert response.status_code == 403


def test_webhook_accepts_valid_signature():
    body, signature = signed_event()
    response = client.post(
        "/webhook",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Signature": signature,
        },
    )
    assert response.status_code == 200


def test_webhook_rejects_expired_event():
    body, signature = signed_event(timestamp=int(time.time()) - 600)
    response = client.post(
        "/webhook",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Signature": signature,
        },
    )
    assert response.status_code == 403
