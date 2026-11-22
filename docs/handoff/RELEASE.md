# Engineering handoff — AEGIS 0.2.0-rc1 (M0–M6)

Verification environment: Linux cloud build workspace (Ubuntu 24.04, 2 vCPU, 8 GiB), native
PostgreSQL 16.15, Python 3.13, Go 1.24.7, Node 22, headless Chrome. Not the maintainers'
laptops. Status labels: **implemented**, **verified**, **partial**, **blocked**, **planned**.

## Module status

| Directive module | Status | Where | Notes |
|---|---|---|---|
| 01 Network Intelligence Engine | partial | `agent/internal/parsers/network.go`, `aegis/baselines.py` | Suricata/Zeek flow, DNS, HTTP, TLS metadata ingested; per-service baselines. No asset inventory or topology inference yet. |
| 02 IDS/IPS Detection | verified (IDS, passive) | rule `ids.suricata.high_severity` | AEGIS consumes Suricata alerts; it does not block inline (no IPS mode). |
| 03 DDoS Defense | verified on synthetic data | `aegis/baselines.py`, `docs/evaluation/ddos-baseline.md` | Detection/signal only; no mitigation automation. |
| 04 Intelligent Firewall Manager | verified (simulation) / blocked (live) | `aegis/responses.py` | Typed proposals, preview, approval, idempotent execute, verify, rollback. Live writes disabled by schema. |
| 05 AI Security Gateway | verified (mock provider) | `aegis/ai/` | Real provider adapters planned. |
| 06 AI Threat Intelligence | planned (disabled in UI) | — | No labeled data to train/evaluate a model honestly. |
| 07 Threat Correlation | verified | `aegis/correlation.py` | Entity/time-window; auth + IDS join one incident. |
| 08 Incident Management | verified | `api/routes_cases.py` | States, reopen, notes, assignment, containment verification, closure reasons, optimistic locking. |
| 09 Orchestration & Response | partial | `aegis/responses.py` | One action type (`block_cidr`); no playbooks. |
| 10 Security Dashboard | verified | `apps/dashboard/` | 15 working pages, 3 explicitly disabled (assets, AI threat intel, threat intel). |
| Endpoint agent (Linux) | verified | `agent/` | Real binary E2E test against the API. |
| Endpoint agent (Windows live log) | partial | `agent/internal/runner/windows_live.go` | Compiles; parser verified; live collection not run. |
| Threat-intel feeds | planned | — | Needs connectors, licensing and outbound data policy. |

## How to run (verified path, no Docker)

```bash
psql -U postgres -v owner_password=… -v app_password=… -v dbname=aegis -f infrastructure/database/bootstrap.sql
python -m venv .venv && . .venv/bin/activate && pip install -e "backend[dev]"
(cd apps/dashboard && npm ci)
export AEGIS_DB_OWNER_PASSWORD=… AEGIS_DB_APP_PASSWORD=… AEGIS_JWT_SECRET=… AEGIS_DEV_PASSWORD=…
scripts/dev-local.sh            # migrate, seed dev users + simulated resource, API, worker, UI
```

Demo flow (Section 20.3): sign in as `analyst@demo.local` → Incidents → *Import sample data*
for `auth-bruteforce-demo`, then `ids-correlation-demo` and `ddos-baseline-demo` → follow an
incident to its events (source / collector / ingest times) → re-import: counts stay stable →
sign in as `analyst@other.local`: nothing visible → AI gateway: try a document saying
"ignore previous instructions…" (flagged, no tool runs) → Response actions: propose as
`proposer@demo.local`, approve and execute as `approver@demo.local` (simulation; host
untouched) → System health shows required vs optional components.

Agent: see `agent/README.md`; enrollment tokens from *Agent management* (tenant admin).

## Verification commands and results (this build)

| Command | Result |
|---|---|
| `scripts/test.sh` (with `AEGIS_TEST_ADMIN_URL`) | ALL GATES PASSED: 58 backend tests, 19 Go tests (`-race`), dashboard build, `npm audit` 0, secret scan 0 |
| `python -m aegis.cli ai-eval` | 26 cases: 23 pass, 3 known deviations (2 FP, 1 FN), 0 unexpected |
| `python scripts/benchmark.py --rate 100 --seconds 180` | see `docs/evaluation/benchmark.md` |
| `pip-audit` on a clean runtime venv | no known vulnerabilities |
| Browser walk-through (headless Chrome, Playwright) | all pages load with real data; no page errors |

## Coverage gaps (not verified here, and why)

1. **Docker Compose / images** — container registry unreachable from the build environment.
   First action for the maintainers: `docker compose up --build` on a laptop.
2. **GitHub Actions** — never executed; no GitHub account was linked to the build session.
3. **Windows runtime** — no Windows host. CI includes `windows-2022` for agent unit tests;
   the live `wevtutil` collector needs a manual test with an account in *Event Log Readers*.
4. **govulncheck / gitleaks** — Go proxy and GitHub downloads unreachable; both run in CI.
5. **15-minute benchmark** — only 3 minutes were run.
6. **Live firewall connectors** — intentionally not implemented; require explicitly
   authorized disposable infrastructure and a documented acceptance record.

## Known limitations

- Threshold rules use tumbling windows (bursts split across a boundary can be missed).
- Login throttling and AI budget per day are per-process / per-day counters without a shared
  rate-limit store; multiple API replicas need Redis or equivalent.
- No refresh tokens, MFA or SSO. JWT secret rotation is manual.
- Redaction is key-based; secrets inside free text are not detected.
- AI injection checks are patterns; paraphrases evade them (measured). Safety relies on the
  broker and human approval, not on detection.
- DDoS baseline has no seasonality model and a single vantage point; a legitimate surge of
  *new* clients with high errors would alert.
- Late events after a closed baseline minute are counted but the minute is not re-evaluated.
- Agent: rotation by rename is detected on Linux (inode) but only by truncation on Windows;
  lines written to a rotated file after the last poll can be missed.
- The worker has no heartbeat endpoint; its health is inferred from queue age.
- Audit log is append-only for the application role but not cryptographically chained.

## Migration and operator notes

- Migrations `0001`–`0005` are forward-only after 0001 (restore from backup to roll back);
  upgrade from 0001 with data is tested; concurrent startup applies them exactly once.
- Backups: `pg_dump -Fc`; restore verified to preserve the evidence chain and RLS policies.
- Roles: run migrations as `aegis_owner`, the API/worker as `aegis_app` (never the owner).

## Next actionable issues

1. Push to GitHub, run CI, fix anything platform-specific it finds (Windows agent tests).
2. Run the Compose stack on a laptop; record results in this file.
3. Windows: manual test of the live Security log collector under a least-privilege account.
4. Sliding-window threshold kind with the same fingerprint guarantees.
5. Worker heartbeat + `/system/status` from real liveness rather than queue age.
6. Shared rate-limit store and refresh tokens before any multi-replica deployment.
