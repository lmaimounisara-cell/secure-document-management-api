# Secure Document Management API

A local applied-cryptography lab demonstrating API authentication, role-based authorization, document integrity checks, and signed audit events. Built with FastAPI.

> **Status:** educational prototype, not production-ready. Do not use real documents, personal data, or production credentials.

## Security features demonstrated

- JWT bearer tokens with a one-hour expiry.
- bcrypt password hashing for demo users configured through local environment variables.
- Role checks for `employee`, `auditor`, and `admin`.
- SHA-256 fingerprints for uploaded documents and an integrity-check endpoint.
- HMAC-SHA256 signatures for audit webhooks, verified using constant-time comparison.
- A 60-second event timestamp window and in-memory duplicate-event detection.
- Local HTTPS can be enabled for the API with a locally generated development certificate.

## Architecture

```text
Client
  | HTTPS + JWT bearer token
  v
FastAPI document service ---- HMAC-SHA256 webhook ----> Audit service
  |                                                      |
  +-- storage/ (uploaded files)                         +-- verifies signature
  +-- metadata.json (SHA-256 and upload metadata)       +-- timestamp / replay checks
```

See [docs/architecture.md](docs/architecture.md) and [docs/security-design.md](docs/security-design.md).

## Local setup

Requirements: Python 3.10+ (a current supported Python version is recommended).

1. Create and activate a virtual environment.
2. Install dependencies: `pip install -r requirements.txt`.
3. Copy `.env.example` to `.env`.
4. Generate two different random secrets locally and set `JWT_SECRET` and `WEBHOOK_SECRET`; set three local demo passwords. Never commit `.env`.
5. Start the audit service in terminal 1: `uvicorn audit_server:app --host 127.0.0.1 --port 9000`.
6. Start the document service in terminal 2: `uvicorn server:app --host 127.0.0.1 --port 8000`.
7. Open `http://127.0.0.1:8000/docs` for the local API documentation. This default command is HTTP on loopback; use the documented local TLS procedure if you need to demonstrate HTTPS.

The demo accounts are `alice` (employee), `bob` (auditor), and `charlie` (admin). Their passwords are the values you configure in your local `.env`; there are no default passwords in the source.

## Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/login` | Exchange demo credentials for a JWT |
| `GET` | `/documents` | List document metadata for an authenticated user |
| `POST` | `/documents` | Upload a document (employee/admin) |
| `GET` | `/admin/integrity` | Verify stored documents (auditor/admin) |
| `POST` | audit service `/webhook` | Verify signed audit events |

## Limitations and next steps

This is a learning project. The prototype uses local JSON metadata and filesystem storage, and its replay cache is in memory; state is not durable across restarts or shared across workers. File size limits, stronger filename policy, safe atomic writes, persistent replay storage, production identity management, rate limiting, structured audit persistence, and automated security tests should be added before any production use.

See [docs/testing.md](docs/testing.md) for the verification plan.
