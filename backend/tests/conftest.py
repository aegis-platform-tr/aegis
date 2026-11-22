"""Test harness: every test session gets a fresh PostgreSQL database, migrated with the owner
role, used by the API/worker through the non-owner runtime role (so RLS is exercised).

Required environment:
  AEGIS_TEST_ADMIN_URL      superuser URL, e.g. postgresql+psycopg://postgres:pw@127.0.0.1:5432/postgres
Optional:
  AEGIS_TEST_OWNER_PASSWORD / AEGIS_TEST_APP_PASSWORD (default: generated per run)
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
FIXTURE = REPO / "sample_data/fixtures/auth-bruteforce-demo.json"
DEV_PASSWORD = "test-only-Passw0rd!"


def _admin_url() -> str:
    url = os.environ.get("AEGIS_TEST_ADMIN_URL")
    if not url:
        pytest.exit("AEGIS_TEST_ADMIN_URL is required to run the test suite", returncode=2)
    return url


def provision_database(admin_url: str, dbname: str, owner_pw: str, app_pw: str) -> None:
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        for role, extra in (
            ("aegis_owner", ""),
            ("aegis_app", " NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"),
        ):
            exists = c.execute(
                text("SELECT 1 FROM pg_roles WHERE rolname=:r"), {"r": role}
            ).scalar()
            if not exists:
                c.execute(text(f"CREATE ROLE {role} LOGIN{extra}"))
        c.execute(text(f"ALTER ROLE aegis_owner PASSWORD '{owner_pw}'"))
        c.execute(text(f"ALTER ROLE aegis_app PASSWORD '{app_pw}'"))
        c.execute(text(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)'))
        c.execute(text(f'CREATE DATABASE "{dbname}" OWNER aegis_owner'))
    admin.dispose()
    db_admin = create_engine(make_url(admin_url).set(database=dbname), isolation_level="AUTOCOMMIT")
    with db_admin.connect() as c:
        c.execute(text("REVOKE ALL ON SCHEMA public FROM PUBLIC"))
        c.execute(text("ALTER SCHEMA public OWNER TO aegis_owner"))
    db_admin.dispose()


def role_url(admin_url: str, dbname: str, role: str, pw: str) -> str:
    return (
        make_url(admin_url)
        .set(username=role, password=pw, database=dbname)
        .render_as_string(hide_password=False)
    )


def run_cli(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "aegis.cli", *args],
        cwd=BACKEND,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@pytest.fixture(scope="session")
def db_env() -> Iterator[dict[str, str]]:
    admin_url = _admin_url()
    owner_pw = os.environ.get("AEGIS_TEST_OWNER_PASSWORD") or secrets.token_urlsafe(16)
    app_pw = os.environ.get("AEGIS_TEST_APP_PASSWORD") or secrets.token_urlsafe(16)
    dbname = f"aegis_test_{secrets.token_hex(4)}"
    provision_database(admin_url, dbname, owner_pw, app_pw)
    env = {
        **os.environ,
        "AEGIS_PROFILE": "local-demo",
        "AEGIS_MIGRATION_DATABASE_URL": role_url(admin_url, dbname, "aegis_owner", owner_pw),
        "AEGIS_DATABASE_URL": role_url(admin_url, dbname, "aegis_app", app_pw),
        "AEGIS_JWT_SECRET": secrets.token_urlsafe(48),
        "AEGIS_DEV_PASSWORD": DEV_PASSWORD,
        "AEGIS_FIXTURES_DIR": str(REPO / "sample_data/fixtures"),
        "AEGIS_LOG_LEVEL": "WARNING",
    }
    for args in (("migrate",), ("seed-dev",)):
        res = run_cli(*args, env=env)
        assert res.returncode == 0, res.stderr
    os.environ.update(env)
    from aegis.config import get_settings
    from aegis.db import _session_factory, get_engine

    get_settings.cache_clear()
    get_engine.cache_clear()
    _session_factory.cache_clear()
    yield {
        **env,
        "_ADMIN_URL": admin_url,
        "_DBNAME": dbname,
        "_OWNER_PW": owner_pw,
        "_APP_PW": app_pw,
    }
    get_engine().dispose()
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)'))
    admin.dispose()


@pytest.fixture(autouse=True)
def clean_data(db_env: dict[str, str]) -> Iterator[None]:
    """Each test starts with no events/alerts/incidents (tenants, users and rules persist)."""
    from aegis.api.routes_auth import failures

    failures.reset()
    owner = owner_engine(db_env)  # superuser: cleanup must bypass RLS
    with owner.begin() as c:
        keep = {"tenants", "users", "detection_rules", "alembic_version"}
        tables = [
            r[0]
            for r in c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'"))
            if r[0] not in keep
        ]
        c.execute(text(f"TRUNCATE {', '.join(tables)} RESTART IDENTITY CASCADE"))
        c.execute(text("DELETE FROM detection_rules WHERE tenant_id IS NOT NULL"))
    owner.dispose()
    yield


@pytest.fixture()
def client(db_env: dict[str, str]) -> Iterator[Any]:
    from fastapi.testclient import TestClient

    from aegis.api.app import create_app

    with TestClient(create_app()) as c:
        yield c


def login(client: Any, username: str = "analyst@demo.local") -> dict[str, str]:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": DEV_PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def fixture_events() -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = json.loads(FIXTURE.read_text())["events"]
    return events


def owner_engine(db_env: dict[str, str]) -> Any:
    """Superuser engine on the test database for assertions. The owner role is itself
    subject to FORCE ROW LEVEL SECURITY, so it cannot be used to inspect tenant data."""
    return create_engine(make_url(db_env["_ADMIN_URL"]).set(database=db_env["_DBNAME"]))


def app_engine(db_env: dict[str, str]) -> Any:
    return create_engine(db_env["AEGIS_DATABASE_URL"])
