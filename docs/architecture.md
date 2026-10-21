# Architecture

## Components

1. **Client:** calls the document API and sends a JWT bearer token after login.
2. **Document API (`server.py`):** authenticates demo credentials, issues/verifies JWTs, checks roles, stores uploaded files, records SHA-256 fingerprints, and sends signed audit events.
3. **Local file store:** `storage/` holds uploaded files; `metadata.json` records the uploader, SHA-256 fingerprint, and timestamp. Both are runtime data and must not be committed.
4. **Audit service (`audit_server.py`):** verifies HMAC-SHA256 over the raw request body, checks event age, and rejects duplicate event IDs in the current process.

## Trust boundaries

- Client to API: bearer token is a credential; use HTTPS when transmitting it beyond loopback.
- API to audit service: the shared webhook secret authenticates event integrity and origin. Keep it private and use a distinct value from the JWT secret.
- Runtime files: uploaded documents and metadata may contain confidential information and are excluded from version control.

## Data flow

```text
Login credentials -> bcrypt verification -> signed JWT
JWT + document request -> token validation -> role authorization
Upload -> file storage -> SHA-256 fingerprint + metadata -> HMAC-signed event
Audit webhook -> signature verification -> timestamp check -> duplicate event check
Integrity request -> recompute SHA-256 -> compare with metadata
```
