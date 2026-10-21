"""Secure Document Management API demo (local security lab)."""
import datetime
import hashlib
import hmac
import json
import os
import time
import uuid
from pathlib import Path

import bcrypt
import jwt
import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
AUDIT_URL = os.getenv("AUDIT_URL", "http://127.0.0.1:9000/webhook")
ALGORITHM = "HS256"
TOKEN_LIFETIME_HOURS = 1
STORAGE_DIR = Path(os.getenv("STORAGE_DIR", "storage"))
METADATA_FILE = Path(os.getenv("METADATA_FILE", "metadata.json"))

if not JWT_SECRET or not WEBHOOK_SECRET:
    raise RuntimeError("Set JWT_SECRET and WEBHOOK_SECRET in your local .env file.")
if len(JWT_SECRET) < 32 or len(WEBHOOK_SECRET) < 32:
    raise RuntimeError("JWT_SECRET and WEBHOOK_SECRET must each be at least 32 characters.")

# Demo credentials are supplied through local environment variables, never source code.
DEMO_USERS = {
    "alice": (os.getenv("DEMO_EMPLOYEE_PASSWORD"), "employee"),
    "bob": (os.getenv("DEMO_AUDITOR_PASSWORD"), "auditor"),
    "charlie": (os.getenv("DEMO_ADMIN_PASSWORD"), "admin"),
}
USERS_DB = {
    username: {"password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(), "role": role}
    for username, (password, role) in DEMO_USERS.items()
    if password
}

STORAGE_DIR.mkdir(parents=True, exist_ok=True)
if not METADATA_FILE.exists():
    METADATA_FILE.write_text("{}", encoding="utf-8")

app = FastAPI(title="Secure Document Management API")
security = HTTPBearer()


class LoginSchema(BaseModel):
    username: str
    password: str


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def create_jwt_token(username: str, role: str) -> str:
    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=TOKEN_LIFETIME_HOURS)
    payload = {"sub": username, "role": role, "exp": expiration}
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        return jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


def require_roles(allowed_roles: list[str]):
    def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        if current_user.get("role") not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient privileges")
        return current_user
    return role_checker


def compute_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def generate_hmac_signature(secret: str, payload_bytes: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()


@app.post("/login")
def login(credentials: LoginSchema):
    user = USERS_DB.get(credentials.username)
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return {"access_token": create_jwt_token(credentials.username, user["role"]), "token_type": "bearer"}


@app.get("/documents")
def get_documents(current_user: dict = Depends(require_roles(["employee", "auditor", "admin"]))):
    return {"documents": json.loads(METADATA_FILE.read_text(encoding="utf-8"))}


@app.post("/documents")
async def upload_document(
    file: UploadFile = File(...),
    current_user: dict = Depends(require_roles(["employee", "admin"])),
):
    content = await file.read()
    filename = Path(file.filename or "").name
    if not filename or filename in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid filename")
    file_path = STORAGE_DIR / filename
    file_path.write_bytes(content)

    file_sha256 = compute_sha256(content)
    timestamp_now = int(time.time())
    metadata = json.loads(METADATA_FILE.read_text(encoding="utf-8"))
    metadata[filename] = {"uploaded_by": current_user["sub"], "sha256": file_sha256, "timestamp": timestamp_now}
    METADATA_FILE.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    event_data = {
        "event_id": f"evt-{uuid.uuid4()}", "event": "document_uploaded",
        "user": current_user["sub"], "file": filename, "sha256": file_sha256,
        "timestamp": timestamp_now,
    }
    raw_payload = json.dumps(event_data, separators=(",", ":")).encode("utf-8")
    signature = generate_hmac_signature(WEBHOOK_SECRET, raw_payload)
    try:
        response = requests.post(
            AUDIT_URL, data=raw_payload,
            headers={"X-Signature": signature, "Content-Type": "application/json"}, timeout=5,
        )
        audit_status = f"audit HTTP {response.status_code}"
    except requests.RequestException:
        audit_status = "audit service unreachable"

    return {"filename": filename, "sha256": file_sha256, "status": "Document saved", "audit": audit_status}


@app.get("/admin/integrity")
def check_integrity(current_user: dict = Depends(require_roles(["auditor", "admin"]))):
    metadata = json.loads(METADATA_FILE.read_text(encoding="utf-8"))
    report = {}
    for filename, info in metadata.items():
        file_path = STORAGE_DIR / Path(filename).name
        if not file_path.exists():
            report[filename] = "MISSING"
            continue
        current_hash = compute_sha256(file_path.read_bytes())
        report[filename] = "OK" if current_hash == info["sha256"] else "MODIFIED"
    return {"integrity_report": report}
