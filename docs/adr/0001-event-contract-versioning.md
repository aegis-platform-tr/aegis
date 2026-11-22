# ADR-0001: Event contract versioning

Status: accepted (M1)

**Context.** Producers (fixture import, future agent, future adapters) and consumers (rules,
UI) must evolve independently without silent breakage.

**Decision.** The public ingest shape is `EventIn` in `backend/aegis/contracts.py`. The JSON
Schema in `contracts/events/event-envelope.v1.schema.json` is generated from it and CI fails
on drift. Every event carries `schema_version`; the server accepts an explicit allow-list
(currently `1.0`). Unknown fields are rejected (`extra=forbid`). Server-assigned fields
(`event_id`, `tenant_id`, `ingested_at`, `producer_id`, `provenance`) cannot be supplied.
Additive optional fields → minor version; renames/removals/semantic changes → new major
version, accepted side by side during migration.

**Consequences.** Strictness surfaces producer bugs immediately (per-item `rejected`
results). Producers must upgrade deliberately. Hand-written TypeScript types in the dashboard
must be kept in sync (generation is a follow-up).
