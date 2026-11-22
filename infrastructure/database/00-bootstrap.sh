#!/bin/sh
# Runs once inside the postgres container on first start (docker-entrypoint-initdb.d).
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v owner_password="$AEGIS_DB_OWNER_PASSWORD" -v app_password="$AEGIS_DB_APP_PASSWORD" \
  -v dbname=aegis -f /aegis/bootstrap.sql
