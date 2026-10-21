# Testing and verification plan

The following cases must be tested before claiming the controls work end to end. Test evidence should use synthetic documents and fake credentials only.

- Authentication: valid demo credentials return a token; invalid credentials return HTTP 401.
- Token validation: missing, malformed, expired, and incorrectly signed tokens are rejected.
- Authorization: employee can upload; employee cannot call the integrity endpoint; auditor can check integrity; admin can upload and check integrity.
- Integrity: newly uploaded file reports `OK`; modified content reports `MODIFIED`; missing content reports `MISSING`.
- Audit signature: valid HMAC is accepted; missing or incorrect signature is rejected.
- Anti-replay: stale timestamps are rejected; a repeated event ID is rejected within the same running process.
- Data hygiene: verify `.env`, private keys, runtime files, and archives are not staged by Git.

Do not describe these tests as passing until automated tests have been implemented and run.
