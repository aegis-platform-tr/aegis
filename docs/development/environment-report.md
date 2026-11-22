# M0 — Environment report (2026-11-22)

Environment in which M1 was built and verified: a Linux cloud workspace (Ubuntu 24.04,
x86_64), not the maintainer's laptop.

| Tool | Version | Used for |
|---|---|---|
| Python | 3.13.18 (project targets ≥ 3.12) | backend |
| PostgreSQL | 16.15 (native binaries) | all tests and the end-to-end run |
| Node.js | 22.23.5 | dashboard |
| Go | 1.24.7 | not used in M1 (agent is M2) |
| Docker | 29.10.0 (daemon runs) | `docker compose config` validation only |

Resolved backend libraries: FastAPI 0.165, SQLAlchemy 2.1, Alembic 1.20, psycopg 3.3,
Pydantic 2.14, argon2-cffi, PyJWT. Dashboard: React 19.3, Vite 8.3, TypeScript 7.0.

## Constraints that changed what could be verified

- **No container registry access.** `docker pull postgres:16-alpine` fails, so images could
  not be built and the Compose stack was **not run**. Compose syntax was validated with
  `docker compose config`. Everything else was verified against native PostgreSQL 16.
- **No GitHub account linked** to the build session, so nothing was pushed and the CI
  workflow has not executed yet.
- Package registries (PyPI, npm) were reachable.

## Maintainer target environment (from project notes)

Windows laptop with Kali Linux under WSL. The non-Docker path (`scripts/dev-local.sh`) works
in WSL with PostgreSQL 16 installed via apt; Docker Desktop with the WSL backend runs the
Compose path.
