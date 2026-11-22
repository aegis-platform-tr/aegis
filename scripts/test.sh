#!/usr/bin/env bash
# Full local verification gate. Needs AEGIS_TEST_ADMIN_URL (PostgreSQL superuser URL),
# Python venv with backend[dev], Go 1.24+ and Node 22+.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "== backend lint/type/contract"
cd "$ROOT/backend"
ruff check . && ruff format --check .
mypy aegis
AEGIS_DATABASE_URL=postgresql+psycopg://x:x@localhost/x \
AEGIS_JWT_SECRET=local-check-not-a-secret-0123456789abcdef \
  python -m aegis.cli export-schema --check
echo "== backend tests (PostgreSQL)"
python -m pytest -p no:warnings
echo "== agent"
cd "$ROOT/agent" && go vet ./... && go test -race -count=1 ./...
echo "== dashboard"
cd "$ROOT/apps/dashboard" && npm run build && npm audit --audit-level=high
echo "== secret scan"
cd "$ROOT" && python scripts/secret_scan.py
echo "ALL GATES PASSED"
