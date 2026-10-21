"""HMAC-authenticated audit webhook receiver for the local security lab."""
import hashlib
import hmac
import json
import os
import time
from collections import deque

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request

load_dotenv()
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
if not WEBHOOK_SECRET:
    raise RuntimeError("Set WEBHOOK_SECRET in your local .env file.")
if len(WEBHOOK_SECRET) < 32:
    raise RuntimeError("WEBHOOK_SECRET must be at least 32 characters.")

MAX_AGE_SECONDS = 60
# In-memory replay tracking is intentionally suitable for a single-process demo only.
SEEN_EVENT_IDS: set[str] = set()
app = FastAPI(title="Secure Document Management Audit Server")


@app.post("/webhook")
async def webhook(request: Request, x_signature: str | None = Header(default=None)):
    body = await request.body()
    if not x_signature:
        raise HTTPException(status_code=403, detail="Missing X-Signature header")
    expected = hmac.new(WEBHOOK_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, x_signature):
        raise HTTPException(status_code=403, detail="Invalid HMAC signature")
    try:
        event = json.loads(body)
        event_id = str(event["event_id"])
        timestamp = int(event["timestamp"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Malformed event")
    if abs(int(time.time()) - timestamp) > MAX_AGE_SECONDS:
        raise HTTPException(status_code=403, detail="Event outside the allowed time window")
    if event_id in SEEN_EVENT_IDS:
        raise HTTPException(status_code=409, detail="Replay detected")
    SEEN_EVENT_IDS.add(event_id)
    print(f"[AUDIT] event={event.get('event')} user={event.get('user')} file={event.get('file')} sha256={event.get('sha256')}")
    return {"status": "accepted", "event_id": event_id}
