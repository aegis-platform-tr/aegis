#!/usr/bin/env bash
# Full local verification. Needs AEGIS_TEST_ADMIN_URL (PostgreSQL superuser URL).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/backend"
ruff check . && ruff format --check .
mypy aegis
AEGIS_DATABASE_URL=postgresql+psycopg://x:x@localhost/x \
AEGIS_JWT_SECRET=local-check-not-a-secret-0123456789abcdef \
  python -m aegis.cli export-schema --check
python -m pytest -p no:warnings
cd "$ROOT/apps/dashboard" && npm run build
