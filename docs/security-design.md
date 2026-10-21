# Security design and review notes

## Implemented in this prototype

- JWT signature validation with an explicit HS256 algorithm allow-list and token expiration.
- bcrypt password hashing for environment-configured demo accounts.
- Role-based access control for document upload and integrity checking.
- SHA-256 content fingerprints to detect changed or missing files.
- HMAC-SHA256 webhook verification using `hmac.compare_digest`.
- A 60-second timestamp tolerance and duplicate event-ID rejection.
- Secrets loaded from local environment configuration rather than embedded in source.

## Important limitations

- Demo users are not a production identity store; passwords are loaded from environment variables and hashes are generated at process start.
- JWTs use a shared symmetric key; key rotation and revocation are not implemented.
- Replay detection is in memory and resets when the process restarts; it is not safe across multiple workers.
- Filesystem and JSON writes are not atomic or concurrency-safe. Upload size limits, malware scanning, and content-type validation are not implemented.
- Filename handling is basic; production code should use generated storage identifiers and enforce a strict filename policy.
- Audit events are printed to standard output rather than stored in a durable, access-controlled audit system.
- HTTPS is not enabled by the default development command. A local development certificate is not a production certificate.
- This project has not yet passed the planned automated test and security review.

## Publication policy

Never commit `.env`, private keys, certificates containing private key material, real documents, runtime `storage/`, `metadata.json`, tokens, or real credentials. `.env.example` contains placeholders only.
