# ADR-0006: Agent identity and delivery

Status: accepted (M2)

**Decision.** Agents enroll with a single-use, tenant-bound, expiring token minted by a tenant
admin and receive their own credential (random 256-bit secret, SHA-256 digest stored, 30-day
expiry, rotation, revocation). Agent requests never carry tenant identity; it is derived from
the credential. Agent ingest reuses the human ingest path with `producer_id = agent:<id>`, so
dedup, redaction, RLS and audit behave identically. The agent is a single Go binary with no
third-party dependencies, a file-per-batch spool and atomically persisted cursors; delivery is
at-least-once with server-side deduplication by `native_id`.

**Alternatives.** mTLS client certificates (stronger, but needs a CA and rotation tooling —
planned for deployment profiles); gRPC streaming (unneeded at this scale); embedded queue
libraries (dependency weight).

**Consequences.** Credential theft from a host lets an attacker submit events as that agent
until revoked; mitigated by per-agent identity, revocation and audit. The live Windows
collector depends on `wevtutil` and is not runtime-verified yet.
