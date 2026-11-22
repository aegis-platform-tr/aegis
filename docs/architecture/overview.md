# Architecture overview (M1)

Components: **API** (FastAPI, sync endpoints, SQLAlchemy 2), **worker** (same codebase,
`python -m aegis.cli worker`), **PostgreSQL 16** (system of record and work queue),
**dashboard** (React SPA, talks to `/api` on the same origin via Vite proxy or nginx).

Request path for ingestion: `POST /api/v1/events` → auth + capability → per-item validation
(`EventIn`) → redaction → `INSERT … ON CONFLICT DO NOTHING` + `work_items` row → commit →
per-item results (`200`, `207` partial, `422` all rejected).

Processing path: worker claims a work item → loads event → active rules (latest active revision)
→ threshold count in the event-time bucket → alert upsert by fingerprint → evidence links →
correlation (advisory lock, open incident within 1 h for the same entity, else create) → mark
done → commit.

Tables: `tenants`, `users`, `revoked_tokens`, `security_events`, `work_items`,
`detection_rules`, `detection_alerts`, `alert_events`, `incidents`, `incident_alerts`,
`incident_transitions`, `audit_logs`. DDL, policies and grants: `backend/migrations/versions/`.

Deviation from the planned layout: backend domains are modules in one package
(`backend/aegis/*.py`) rather than separate `core/`, `ingestion/`, … packages, and the API app
lives in `backend/aegis/api/` instead of `apps/api/`. This keeps M1 small; splitting is
mechanical once modules grow.
