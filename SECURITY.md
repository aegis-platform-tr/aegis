# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
**Security → Report a vulnerability** (private advisory) on this repository. Do not open a
public issue. Include affected version/commit, reproduction steps and impact. We aim to
acknowledge within 7 days. This is a volunteer student project; there is no bug bounty.

## Scope and intended use

AEGIS is defensive software. It must only be used on systems and data you own or are
explicitly authorized to monitor. The project accepts no contributions that add offensive
capability (exploitation, credential theft, evasion, persistence, unauthorized scanning).

## Security model

- Tenant identity comes only from the server-validated credential, never from request bodies.
  Payloads containing `tenant_id` are rejected.
- Tenant isolation is enforced in every query **and** by PostgreSQL row-level security. The
  API/worker connect as `aegis_app`, which owns no tables and has no `BYPASSRLS`.
- `aegis_app` cannot `UPDATE`/`DELETE` events, evidence links, transitions or audit rows.
- Passwords: Argon2id. Tokens: HS256 JWT, 15-minute lifetime, issuer/audience/expiry checked,
  `alg=none` rejected, revocation on logout.
- Inputs are size-bounded (1 MiB body, 500 items, 16 KiB attributes); compressed bodies are
  refused; unknown fields are rejected.
- Credential-like attribute keys are redacted before storage; SQL bound parameters are hidden
  from logs and error text.
- Development credentials exist only in the `local-demo` profile and must be set through
  environment variables. The repository contains no real secrets.

- Agents use single-use, expiring, tenant-bound enrollment tokens and individual, rotatable,
  revocable credentials (only SHA-256 digests are stored).
- AI requests pass a deterministic gateway; model output never grants permissions and write
  tools can only draft response proposals that need independent human approval.
- Response actions run in a simulation adapter; live firewall writes are disabled by schema.

See `docs/security/` for the capability matrix, threat notes and the control mapping.
