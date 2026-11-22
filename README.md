# AEGIS — Autonomous Enterprise Guard & Intelligence System

AEGIS is an open-source, defensive security operations platform: it ingests security
telemetry, normalizes it into a versioned event contract, runs deterministic detection rules,
correlates alerts into incidents and gives analysts an evidence timeline they can follow back
to the underlying events.

> **Status: M1 vertical slice (pre-alpha).** This is a working learning/portfolio system,
> not a production SIEM, SOAR, EDR or IPS. It has no agent yet, no ML, no response actions
> and no external integrations. See [Known limitations](#known-limitations).

**Defensive use only.** AEGIS contains no offensive capability. Use it only on systems and
data you own or are explicitly authorized to monitor. All bundled data is synthetic.

## What works today (M1)

```
analyst ──login──▶ API ──▶ PostgreSQL (event + work item, one transaction)
                              │
                         worker (SKIP LOCKED) ──▶ threshold rule ──▶ alert (fingerprinted)
                                                          └──▶ correlation ──▶ incident
dashboard ◀── incidents · alerts · evidence timeline · event detail ◀── API
```

- Authenticated, tenant-scoped batch ingestion with per-item `accepted / duplicate / rejected`
  results and idempotent replay.
- Event contract v1 ([`contracts/events/`](contracts/events/)), generated from the models and
  checked for drift in CI.
- Credential-like attribute keys are redacted before storage.
- Declarative rule `auth.bruteforce.source_asset` (≥5 `login_failure` per source IP + asset in
  a 5-minute event-time window), with explanation, confidence and an ATT&CK *label*.
- Entity/time-window correlation into incidents, with an explicit state machine, reason-required
  transitions, history and optimistic concurrency (`409` on stale versions).
- Tenant isolation enforced twice: in every query and by PostgreSQL row-level security on a
  non-owner runtime role.
- Append-only audit log for logins, ingest batches and incident transitions.
- React dashboard: login, incident list with filters and paging, incident detail with timeline,
  event detail with provenance, and a one-click synthetic fixture import (local-demo only).

## Quick start (Docker)

```bash
cp .env.example .env          # then replace every change-me value
docker compose up --build -d
docker compose run --rm api python -m aegis.cli seed-dev
```

Open http://127.0.0.1:8080 and sign in as `analyst@demo.local` with the `AEGIS_DEV_PASSWORD`
you set. Click **Import sample data**; an incident appears within a few seconds.

API docs: http://127.0.0.1:8000/api/docs

> The Docker path is defined but was **not executed** in the environment where M1 was built
> (no registry access). The non-Docker path below is the one that was verified end to end.

## Quick start (without Docker)

Requirements: Python 3.12+, Node 22+, PostgreSQL 16.

```bash
psql -U postgres -v owner_password=... -v app_password=... -v dbname=aegis \
     -f infrastructure/database/bootstrap.sql
python -m venv .venv && . .venv/bin/activate && pip install -e "backend[dev]"
(cd apps/dashboard && npm ci)
export AEGIS_DB_OWNER_PASSWORD=... AEGIS_DB_APP_PASSWORD=... \
       AEGIS_JWT_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(48))") \
       AEGIS_DEV_PASSWORD=...
scripts/dev-local.sh          # dashboard: http://127.0.0.1:5173
```

Import the fixture from the command line through the public API instead of the UI:

```bash
cd backend && python -m aegis.cli import-fixture ../sample_data/fixtures/auth-bruteforce-demo.json
```

## Tests

```bash
export AEGIS_TEST_ADMIN_URL=postgresql+psycopg://postgres:<pw>@127.0.0.1:5432/postgres
scripts/test.sh               # ruff, mypy --strict, contract drift, pytest, dashboard build
```

Each test session creates and drops its own database. The suite covers the full flow, replay
idempotency, worker crash/retry, late out-of-order events, parallel duplicate submissions,
parallel workers, tenant isolation (API and RLS), token forgery/expiry/`alg=none`, login
throttling, capability checks, malformed/oversized/compressed input, append-only grants,
concurrent migrations and backup/restore of the evidence chain.

## Repository layout

| Path | Contents |
|---|---|
| `backend/aegis/` | API (`api/`), ingestion, detection, correlation, worker, security, audit |
| `backend/migrations/` | Alembic migrations (schema, RLS policies, grants, built-in rule) |
| `backend/tests/` | PostgreSQL-backed test suite |
| `apps/dashboard/` | React + TypeScript + Vite analyst UI |
| `contracts/events/` | Versioned event envelope JSON Schema |
| `sample_data/fixtures/` | Synthetic fixture packs with expected outcomes |
| `infrastructure/` | Database bootstrap, Dockerfiles, nginx config |
| `docs/` | ADRs, environment report, architecture, security model, handoff |

## Known limitations

- Single detection rule kind (threshold, tumbling window): a burst split across a window
  boundary can go undetected. Sliding windows are planned.
- Login throttling is in-process (one API replica only).
- Access tokens are short-lived (15 min) with no refresh flow; a reload requires sign-in.
- Redaction is key-based; secrets inside free-text values are not detected.
- No agent, network sensor, ML, response actions, SSO/MFA or external integrations yet.
- The Docker Compose stack and CI workflow have not been run yet (see `docs/handoff/M1.md`).

## Roadmap

M2 lightweight agent · M3 analyst workflow & detection lab · M4 explainable anomaly signals ·
M5 safe response proposals with approval · M6 operational hardening. Details:
[`docs/handoff/M1.md`](docs/handoff/M1.md).

## License

Apache-2.0. See [LICENSE](LICENSE), [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md).
