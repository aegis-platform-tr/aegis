"""Contract drift, migrations under concurrent startup, readiness, backup/restore."""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from conftest import fixture_events, login, provision_database, role_url, run_cli
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
