-- AEGIS database bootstrap (run once as a PostgreSQL superuser).
-- Usage:
--   psql -v owner_password="$AEGIS_DB_OWNER_PASSWORD" -v app_password="$AEGIS_DB_APP_PASSWORD" \
--        -v dbname=aegis -f infrastructure/database/bootstrap.sql
-- Roles:
--   aegis_owner  owns the schema and runs migrations only.
--   aegis_app    runtime role for API and worker: DML only, not owner, so RLS applies.
SELECT 'CREATE ROLE aegis_owner LOGIN' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_owner')\gexec
SELECT 'CREATE ROLE aegis_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE'
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app')\gexec
ALTER ROLE aegis_owner PASSWORD :'owner_password';
ALTER ROLE aegis_app PASSWORD :'app_password';
SELECT format('CREATE DATABASE %I OWNER aegis_owner', :'dbname')
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'dbname')\gexec
\connect :dbname
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO aegis_owner;
ALTER SCHEMA public OWNER TO aegis_owner;
