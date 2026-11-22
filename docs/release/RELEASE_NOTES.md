# AEGIS 0.2.0-rc1 — release candidate notes (2026-11-22)

**Not published.** Publication requires explicit maintainer authorization. Every statement
below points to a test, an evaluation document or a manual verification record.

## What is in this release
| Area | Status | Evidence |
|---|---|---|
| Event contract v1, authenticated idempotent ingestion, redaction | verified | `backend/tests/test_m1_flow.py`, `test_security.py` |
| Tenant isolation (API + PostgreSQL RLS) | verified | `test_security.py`, `test_agents.py`, `test_m3_detection.py`, `test_m4_m5.py` |
| Threshold rules, alerts, correlation, incidents, timeline | verified | `test_m1_flow.py`, `test_m3_detection.py` |
| Rule lifecycle (draft/test/publish/rollback), suppressions | verified | `test_m3_detection.py` |
| Service baselines / DDoS signal | verified on synthetic data | `docs/evaluation/ddos-baseline.md` |
| Agent enrollment, rotation, revocation, heartbeats | verified (Linux) | `test_agents.py`, Go tests |
| Agent collectors: linux-auth, suricata-eve, zeek-json, windows-event XML file | verified on fixtures and live file tailing (Linux) | Go tests, `test_real_agent_binary_end_to_end` |
| Agent live Windows Security log collector | **partial**: compiles, not runtime-verified | — (no Windows host); CI matrix includes windows-2022 for unit tests |
| AI Security Gateway (mock provider) | verified | `docs/evaluation/ai-gateway.md`, `test_m4_m5.py` |
| Real AI provider adapters | **planned** (cloud adapter is a non-transmitting stub) | ADR-0008 |
| Response transactions (simulation adapter) | verified | `test_m4_m5.py` |
| Live nftables / Windows Firewall execution | **blocked by design** (render-only); needs authorized disposable infrastructure | ADR-0005 |
| Dashboard (all directive modules; 3 shown as disabled) | verified (browser walk-through) | `docs/handoff/RELEASE.md` |
| Docker Compose stack | **unverified** (registry unreachable in build environment) | `docker compose config` only |
| CI workflow | **unverified** (not yet run on GitHub) | `.github/workflows/ci.yml` |

## Gates run for this candidate
| Gate | Result |
|---|---|
| ruff + `mypy --strict` (backend) | pass |
| Contract drift check | pass |
| Backend tests on PostgreSQL 16 (unit, API, DB, tenant, concurrency, migrations incl. concurrent startup and upgrade from 0001, backup/restore, DB outage, agent binary E2E, AI eval, response failures) | **58 passed** |
| Go `vet` + `test -race` (agent) | pass (19 tests) |
| Dashboard `tsc` + production build | pass |
| `npm audit` (dashboard) | 0 vulnerabilities |
| `pip-audit` (runtime deps, clean venv) | no known vulnerabilities |
| `govulncheck` | **not run**: Go module proxy unreachable from build environment (agent has no third-party modules; stdlib go1.24.7) |
| Secret scan (`scripts/secret_scan.py`) | 0 findings; gitleaks runs in CI only |
| SBOM | `release/sbom/backend-python.cdx.json` (34 runtime components), `dashboard-npm.cdx.json`, `agent-go.txt` |
| Benchmark | `docs/evaluation/benchmark.md` (3-minute run, not 15) |

## Supported platform matrix
| Component | Linux | Windows | macOS |
|---|---|---|---|
| Backend API/worker | verified (Ubuntu 24.04, Py 3.13; targets ≥3.12) | not tested (WSL recommended) | not tested |
| Agent | verified (amd64) | builds (amd64); unit tests in CI; live collector unverified | builds; not tested |
| Dashboard | Chrome (headless) verified | — | — |
| Database | PostgreSQL 16 | — | — |

## Connector matrix
| Connector | Direction | Mode | Status |
|---|---|---|---|
| Linux auth log / journald text | in | agent file tail | verified |
| Suricata EVE JSON | in | agent file tail / fixture | verified (fixtures + live tail) |
| Zeek JSON logs | in | agent file tail / fixture | verified (fixtures + live tail) |
| Windows Security log | in | agent (`wevtutil`) | partial (parser verified) |
| Simulation firewall | out | DB-backed policy | verified |
| nftables | out | render-only dry run | partial (rendering verified) |
| Windows Defender Firewall | out | render-only dry run | partial (rendering verified) |
| Cloud LLM provider | out | disabled stub (never transmits) | planned |
| Threat-intel feeds | in | — | not implemented (UI shows disabled) |

## Known limitations
See `docs/handoff/RELEASE.md#known-limitations`.
