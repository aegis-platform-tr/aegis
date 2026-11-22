# AEGIS — Autonomous Enterprise Guard & Intelligence System

AEGIS is an open-source, defensive security operations platform. It collects telemetry with a
lightweight Go agent, normalizes it into a versioned event contract, runs deterministic and
explainable detections, correlates alerts into incidents, gives analysts an evidence timeline,
puts every AI interaction behind a deterministic security gateway, and turns containment ideas
into typed, independently approved, reversible response transactions.

> **Status: 0.2.0-rc1 (milestones M0–M6 complete in the build environment).** A working
> student/portfolio platform, not a production SIEM/SOAR/EDR. Live firewall writes and real
> cloud AI providers are deliberately not enabled. Honest per-module status:
> [`docs/handoff/RELEASE.md`](docs/handoff/RELEASE.md).

**Defensive use only.** No offensive capability. Use it only on systems and data you own or are
explicitly authorized to monitor. All bundled data is synthetic and uses documentation
address ranges.

```
 Go agent (auth.log, Suricata EVE, Zeek, Windows Security)          analysts (React dashboard)
        │ enrollment token → per-agent credential                         │ JWT, capabilities
        ▼                                                                 ▼
  FastAPI ──► PostgreSQL (events + work queue in one tx, RLS per tenant, append-only audit)
                 │
              worker ──► threshold rules ─► alerts ─► correlation ─► incidents ─► timeline
                     └─► service baselines (DDoS signal) ─┘
  AI gateway ──► policy · redaction · untrusted-data labeling · tool broker · output checks
  Responses ──► propose → preview → independent approval → execute (simulation) → verify → rollback
```

## Highlights

- **Ingestion:** authenticated, tenant-scoped, idempotent (`accepted / duplicate / rejected`
  per item), credential redaction, versioned contract checked for drift in CI.
- **Agent (Go, stdlib only):** strict config with no command fields, crash-safe bounded spool
  with back-pressure, cursors, quarantine, retry/backoff, rotation/revocation.
- **Detection:** versioned declarative rules with dry-run on fixtures, publish/rollback,
  expiring suppressions, IDS and Windows rules, per-service baselines that tell a deployment
  spike from a new-source surge (`docs/evaluation/ddos-baseline.md`).
- **Investigation:** incidents with state machine, reopen, notes, assignment, optimistic
  locking; timeline separates source, collector and server times.
- **AI Security Gateway:** offline mock provider, fail-safe decisions, write tools can only
  draft proposals; 26-case evaluation with measured false positives/negatives
  (`docs/evaluation/ai-gateway.md`).
- **Response:** one typed action (`block_cidr`) with exact diff, protected-path checks,
  separation of duties, idempotency, verification and automatic restore.
- **Isolation:** tenant enforced in every query *and* by PostgreSQL row-level security on a
  non-owner runtime role.

## Quick start (verified path, no Docker)

Requirements: Python 3.12+, Go 1.24+, Node 22+, PostgreSQL 16.

```bash
psql -U postgres -v owner_password=… -v app_password=… -v dbname=aegis \
     -f infrastructure/database/bootstrap.sql
python -m venv .venv && . .venv/bin/activate && pip install -e "backend[dev]"
(cd apps/dashboard && npm ci)
export AEGIS_DB_OWNER_PASSWORD=… AEGIS_DB_APP_PASSWORD=… AEGIS_DEV_PASSWORD=… \
       AEGIS_JWT_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(48))")
scripts/dev-local.sh        # dashboard http://127.0.0.1:5173 · API docs http://127.0.0.1:8000/api/docs
```

Sign in as `analyst@demo.local` (password = `AEGIS_DEV_PASSWORD`) and click **Import sample
data**. The full demo walk-through is in [`docs/handoff/RELEASE.md`](docs/handoff/RELEASE.md).

### Docker (defined, not yet executed)

```bash
cp .env.example .env    # replace every change-me value
docker compose up --build -d && docker compose run --rm api python -m aegis.cli seed-dev
```
Dashboard: http://127.0.0.1:8080. The build environment had no registry access, so this path
has only been validated with `docker compose config`.

### Agent

```bash
cd agent && go build -trimpath -o aegis-agent ./cmd/aegis-agent
./aegis-agent enroll -config examples/agent.linux.json -token-file token.txt
./aegis-agent run -config examples/agent.linux.json
```
See [`agent/README.md`](agent/README.md) for permissions and failure behavior.

## Verification

```bash
export AEGIS_TEST_ADMIN_URL=postgresql+psycopg://postgres:<pw>@127.0.0.1:5432/postgres
scripts/test.sh            # ruff, mypy --strict, contract, 58 PostgreSQL tests, Go -race, UI build, audits, secret scan
```
Release gates and evidence: [`docs/release/RELEASE_NOTES.md`](docs/release/RELEASE_NOTES.md).

## Repository layout

| Path | Contents |
|---|---|
| `backend/aegis/` | API routers, ingestion, detection, baselines, correlation, worker, agents, AI gateway (`ai/`), responses, security, audit |
| `backend/migrations/` | Alembic migrations 0001–0005 (schema, RLS, grants, built-in rules) |
| `backend/tests/` | PostgreSQL-backed tests (incl. real agent E2E, AI eval, response failure modes) |
| `agent/` | Go collection agent |
| `apps/dashboard/` | React + TypeScript + Vite SOC dashboard |
| `contracts/events/` | Event envelope JSON Schema v1 |
| `sample_data/` | Synthetic fixture packs and their deterministic generators |
| `docs/` | ADRs 0001–0008, evaluations, security mapping, release notes, handoff |
| `release/sbom/` | CycloneDX SBOMs (Python, npm) and Go build inputs |

## Team

Built by Muhammed Taha Özer and Kaan Doğan. Working agreement:
[`docs/development/collaboration.md`](docs/development/collaboration.md).

## License

Apache-2.0. See [LICENSE](LICENSE), [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md).
