#!/usr/bin/env bash
# Run AEGIS without Docker against an existing local PostgreSQL 16.
# Prereqs: roles/database created with infrastructure/database/bootstrap.sql, and these set:
#   AEGIS_DB_OWNER_PASSWORD AEGIS_DB_APP_PASSWORD AEGIS_JWT_SECRET AEGIS_DEV_PASSWORD
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
: "${AEGIS_DB_HOST:=127.0.0.1}"
export AEGIS_PROFILE=local-demo
export AEGIS_DATABASE_URL="postgresql+psycopg://aegis_app:${AEGIS_DB_APP_PASSWORD:?}@${AEGIS_DB_HOST}:5432/aegis"
export AEGIS_MIGRATION_DATABASE_URL="postgresql+psycopg://aegis_owner:${AEGIS_DB_OWNER_PASSWORD:?}@${AEGIS_DB_HOST}:5432/aegis"
export AEGIS_FIXTURES_DIR="$ROOT/sample_data/fixtures"
cd "$ROOT/backend"
python -m aegis.cli migrate
python -m aegis.cli seed-dev
python -m aegis.cli api &  API=$!
python -m aegis.cli worker & WORKER=$!
(cd "$ROOT/apps/dashboard" && npm run dev) & UI=$!
trap 'kill $API $WORKER $UI 2>/dev/null' EXIT INT TERM
echo "AEGIS: dashboard http://127.0.0.1:5173  API http://127.0.0.1:8000/api/docs"
wait
