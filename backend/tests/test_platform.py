"""Contract drift, migrations under concurrent startup, readiness, backup/restore."""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from conftest import BACKEND, fixture_events, login, provision_database, role_url, run_cli
from pydantic import ValidationError
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from aegis.contracts import EventIn
from aegis.worker import drain


def test_contract_file_matches_models(db_env: dict[str, str]) -> None:
    res = run_cli("export-schema", "--check", env=db_env)
    assert res.returncode == 0, res.stderr


def test_every_fixture_event_validates_against_contract() -> None:
    for e in fixture_events():
        EventIn.model_validate(e)
    with pytest.raises(ValidationError):
        EventIn.model_validate(fixture_events()[0] | {"event_id": "evt_client_chosen"})


def test_health_and_readiness(client: Any) -> None:
    assert client.get("/api/v1/health").json()["status"] == "ok"
    r = client.get("/api/v1/ready")
    assert r.status_code == 200 and r.json()["checks"] == {"database": "ok", "migrations": "ok"}


def test_concurrent_migrations_apply_exactly_once(db_env: dict[str, str]) -> None:
    dbname = f"aegis_mig_{secrets.token_hex(4)}"
    admin = db_env["_ADMIN_URL"]
    provision_database(admin, dbname, db_env["_OWNER_PW"], db_env["_APP_PW"])
    env = {
        **db_env,
        "AEGIS_MIGRATION_DATABASE_URL": role_url(admin, dbname, "aegis_owner", db_env["_OWNER_PW"]),
    }
    try:
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: run_cli("migrate", env=env), range(3)))
        assert all(r.returncode == 0 for r in results), [r.stderr for r in results]
        eng = create_engine(make_url(admin).set(database=dbname))
        with eng.connect() as c:
            assert c.execute(text("SELECT count(*) FROM alembic_version")).scalar_one() == 1
            assert c.execute(text("SELECT count(*) FROM detection_rules")).scalar_one() == 4
        eng.dispose()
    finally:
        _drop(admin, dbname)


def _drop(admin_url: str, dbname: str) -> None:
    eng = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)'))
    eng.dispose()


def _pg_tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for ver in ("17", "16", "15"):
        p = f"/usr/lib/postgresql/{ver}/bin/{name}"
        if os.path.exists(p):
            return p
    return None


def test_backup_and_restore_preserves_evidence_chain(
    client: Any, db_env: dict[str, str], tmp_path: Any
) -> None:
    pg_dump, pg_restore = _pg_tool("pg_dump"), _pg_tool("pg_restore")
    if not (pg_dump and pg_restore):
        pytest.skip("pg_dump/pg_restore not installed: backup/restore unverified here")
    h = login(client)
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=h)
    drain()
    admin = make_url(db_env["_ADMIN_URL"])
    env = {**os.environ, "PGPASSWORD": admin.password or ""}
    common = [
        "-h",
        admin.host or "127.0.0.1",
        "-p",
        str(admin.port or 5432),
        "-U",
        admin.username or "postgres",
    ]
    dump = tmp_path / "aegis.dump"
    subprocess.run(
        [pg_dump, *common, "-Fc", "-f", str(dump), db_env["_DBNAME"]],
        env=env,
        check=True,
        capture_output=True,
        timeout=120,
    )
    restored = f"aegis_restore_{secrets.token_hex(4)}"
    provision_database(db_env["_ADMIN_URL"], restored, db_env["_OWNER_PW"], db_env["_APP_PW"])
    try:
        subprocess.run(
            [pg_restore, *common, "-d", restored, "--no-owner", "--role=aegis_owner", str(dump)],
            env=env,
            check=True,
            capture_output=True,
            timeout=120,
        )
        q = (
            "SELECT (SELECT count(*) FROM security_events), (SELECT count(*) FROM "
            "detection_alerts), (SELECT count(*) FROM alert_events), (SELECT count(*) FROM "
            "incidents), (SELECT count(*) FROM incident_alerts)"
        )
        src = create_engine(make_url(db_env["_ADMIN_URL"]).set(database=db_env["_DBNAME"]))
        dst = create_engine(make_url(db_env["_ADMIN_URL"]).set(database=restored))
        with src.connect() as a, dst.connect() as b:
            assert (
                tuple(a.execute(text(q)).one())
                == tuple(b.execute(text(q)).one())
                == (12, 1, 7, 1, 1)
            )
            # RLS policies survive the restore.
            assert b.execute(text("SELECT count(*) FROM pg_policies")).scalar_one() >= 7
        src.dispose()
        dst.dispose()
    finally:
        _drop(db_env["_ADMIN_URL"], restored)


def test_overview_counts_are_real_and_tenant_scoped(client: Any) -> None:
    h = login(client)
    empty = client.get("/api/v1/overview", headers=h).json()
    assert empty["events_total"] == 0 and empty["network"]["status"] == "no network telemetry yet"
    assert empty["last_event_ingested_at"] is None
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=h)
    q = client.get("/api/v1/system/status", headers=h).json()["queue"]
    assert q["pending"] == 12
    drain()
    o = client.get("/api/v1/overview", headers=h).json()
    assert o["events_total"] == 12 and o["incidents_by_status"] == {"new": 1}
    assert o["alerts_by_severity"] == {"high": 1} and o["pipeline"]["pending"] == 0
    assert o["events_by_origin"] == {"synthetic": 12}
    other = client.get("/api/v1/overview", headers=login(client, "analyst@other.local")).json()
    assert other["events_total"] == 0 and other["incidents_by_status"] == {}


def test_upgrade_from_m1_schema_preserves_evidence(db_env: dict[str, str]) -> None:
    """Upgrade path: a database created at the first released revision (0001) with data in it
    migrates to head without losing the evidence chain."""
    dbname = f"aegis_upg_{secrets.token_hex(4)}"
    admin = db_env["_ADMIN_URL"]
    provision_database(admin, dbname, db_env["_OWNER_PW"], db_env["_APP_PW"])
    env = {
        **db_env,
        "AEGIS_MIGRATION_DATABASE_URL": role_url(admin, dbname, "aegis_owner", db_env["_OWNER_PW"]),
    }
    try:
        code = (
            "from alembic import command; from alembic.config import Config; "
            "command.upgrade(Config('alembic.ini'), '0001_initial')"
        )
        res = subprocess.run(
            [sys.executable, "-c", code],
            cwd=BACKEND,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert res.returncode == 0, res.stderr
        eng = create_engine(make_url(admin).set(database=dbname))
        with eng.begin() as c:
            c.execute(text("INSERT INTO tenants VALUES ('tenant_old', 'Old', now())"))
            c.execute(
                text(
                    "INSERT INTO security_events (id, tenant_id, producer_id, source_adapter, "
                    "source_adapter_version, source_native_id, schema_version, event_category, "
                    "event_type, observed_at, origin) VALUES ('evt_old', 'tenant_old', 'user:x', "
                    "'fixture', '1', 'n1', '1.0', 'authentication', 'login_failure', now(), "
                    "'synthetic')"
                )
            )
            c.execute(
                text(
                    "INSERT INTO detection_alerts (id, tenant_id, rule_id, rule_revision, "
                    "fingerprint, title, severity, confidence, group_key, window_start, "
                    "window_end, event_count, first_event_at, last_event_at, explanation, "
                    "origin) VALUES ('alr_old', 'tenant_old', 'auth.bruteforce.source_asset', 1, "
                    "'fp', 't', 'high', 0.7, '{}', now(), now(), 1, now(), now(), 'old', "
                    "'synthetic')"
                )
            )
            c.execute(text("INSERT INTO alert_events VALUES ('alr_old', 'evt_old', 'tenant_old')"))
        res = run_cli("migrate", env=env)
        assert res.returncode == 0, res.stderr
        with eng.connect() as c:
            row = c.execute(
                text(
                    "SELECT a.suppressed, a.evidence_quality, r.status, r.published_by "
                    "FROM detection_alerts a JOIN detection_rules r ON r.id = a.rule_id "
                    "AND r.revision = a.rule_revision WHERE a.id = 'alr_old'"
                )
            ).one()
            assert tuple(row) == (False, "direct", "active", "aegis-core")
            assert c.execute(text("SELECT count(*) FROM alert_events")).scalar_one() == 1
            head = c.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        from aegis.api.app import migration_head

        assert head == migration_head()
        eng.dispose()
    finally:
        _drop(admin, dbname)


def test_database_outage_is_reported_and_survived(db_env: dict[str, str]) -> None:
    """Liveness stays up, readiness reports the outage, and the worker backs off instead of
    crashing. Port 9 on localhost has nothing listening."""
    import socket
    import time

    import httpx

    bad = {**db_env, "AEGIS_DATABASE_URL": "postgresql+psycopg://x:y@127.0.0.1:9/none"}
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    api = subprocess.Popen(
        [sys.executable, "-m", "aegis.cli", "api", "--port", str(port)],
        cwd=BACKEND,
        env=bad,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    worker = subprocess.Popen(
        [sys.executable, "-m", "aegis.cli", "worker"],
        cwd=BACKEND,
        env=bad,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                if httpx.get(base + "/api/v1/health", timeout=0.5).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.1)
        r = httpx.get(base + "/api/v1/ready", timeout=10)
        assert r.status_code == 503 and r.json()["checks"]["database"] == "unavailable"
        login = httpx.post(
            base + "/api/v1/auth/login",
            timeout=10,
            json={"username": "analyst@demo.local", "password": "whatever-123"},
        )
        assert (
            login.status_code == 503 and login.json()["error"]["code"] == "dependency_unavailable"
        )
        assert "Traceback" not in login.text
        assert "y@127.0.0.1" not in login.text  # no connection string leakage
        time.sleep(3)
        assert worker.poll() is None  # still alive, backing off
    finally:
        for p in (api, worker):
            p.terminate()
            p.wait(timeout=10)
    assert "database unavailable; backing off" in (worker.stderr.read() if worker.stderr else "")
