# Acceptance record — 2026-11-22 (build environment)

Environment: Linux build workspace, 2 vCPU, PostgreSQL 16.15, fresh `aegis` database
(bootstrap → migrate → seed-dev), API + worker as separate processes.

## Section 20.3 flow — `scripts/acceptance.py` (9/9 PASS)
1. readiness (database + migrations ok) — PASS
2. fixture import through the normal path (12 + 2 + 2,879 events, 0 rejected); every event
   labeled synthetic — PASS
3. evidence chain incident → alerts → events with distinct source/receipt/evaluation times
   (auth + IDS alerts in one incident) — PASS
4. re-import (12 duplicates, 0 new) and worker restart: event/alert/incident counts unchanged,
   0 dead letters — PASS
5. other tenant: incident detail 404, lists/counts/network empty, AI summary 404 — PASS
6. AI: benign `allow`; policy provider `none` → `deny` with no provider call; mock outage →
   `dependency_unavailable`; audit holds no prompt text; readiness unaffected — PASS
7. simulated rule: preview coverage known, host unchanged, approval by a second user,
   execute verified; propose/preview/approve/execute audited — PASS
8. empty tenant shows "no network telemetry yet" and null last-ingest (not zero); live
   firewall adapters reported `disabled` — PASS

## Degraded state (manual)
Worker stopped, 3 events ingested: API accepted them; after 62 s `/system/status` reported
`worker: degraded: backlog older than 60 s` (3 pending). Worker restarted: backlog processed,
status `idle`, nothing lost.

## Container-layout run (Docker image emulation)
Dockerfile layout reproduced on disk (`/app/backend`, `/app/contracts`, `/app/sample_data`),
non-editable install in a clean venv, application tree **read-only**, processes run as a
**non-root** user, `PYTHONDONTWRITEBYTECODE=1`. Two `migrate` processes started concurrently
→ both "at head", applied once. `seed-dev`, contract check, readiness `ready`; imported all
three fixture packs (2,893 events, 0 dead letters) → 3 incidents; AI summary `allow`;
response executed `verified`; replay 12 duplicates; other tenant 0 events; no ERROR log lines.
Not covered: actual image build, nginx container, Compose networking (registry unreachable).

## Route sweep (`backend/tests/test_route_sweep.py`)
All 54 OpenAPI operations: every non-public route returns 401 without credentials; every
id-taking route refuses another tenant's ids even for a user holding every role; every list
route returns nothing from the other tenant. Mutation check: running the same sweep with a
same-tenant user reports 6 leaks, so the sweep does detect them.
