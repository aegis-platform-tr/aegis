# ADR-0003: Identity and authorization

Status: accepted (M1)

**Decision.** M1 uses database-provisioned identities with Argon2id password hashes and
short-lived HS256 access tokens (15 min; `iss`, `aud`, `exp`, `nbf`, `jti` required). Logout
revokes the `jti`. Tokens live in browser memory only (not `localStorage`), and are sent as a
bearer header, so cookies/CSRF are not involved. Authorization is capability-based
(`docs/security/capability-matrix.md`), checked on the server for every route; the UI only
hides controls. Login failures are throttled per username and audited; unknown users and
wrong passwords return the same response with equalized hashing time.

Development users are created only by `seed-dev`, which refuses to run outside the
`local-demo` profile and takes the password from `AEGIS_DEV_PASSWORD`.

**Deferred.** Refresh tokens, MFA, OIDC/SSO, service credentials for agents (M2 will use
per-agent enrollment tokens), shared throttling store.
