"""Authentication, authorization, tenant isolation and input-hardening tests."""

from __future__ import annotations

import gzip
import json
import time
from typing import Any

import jwt
from conftest import DEV_PASSWORD, app_engine, fixture_events, login, owner_engine
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from aegis.worker import drain


def _seed_incident(client: Any) -> tuple[dict[str, str], str, str, str]:
    h = login(client)
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=h)
    drain()
    alert = client.get("/api/v1/alerts", headers=h).json()["items"][0]
    event_id = client.get(f"/api/v1/alerts/{alert['alert_id']}", headers=h).json()["event_ids"][0]
    return h, event_id, alert["alert_id"], alert["incident_id"]


# ---- Tenant isolation ---------------------------------------------------------------------


def test_other_tenant_cannot_read_detail_list_or_counts(
    client: Any, db_env: dict[str, str]
) -> None:
    _, event_id, alert_id, incident_id = _seed_incident(client)
    other = login(client, "analyst@other.local")
    for path in (
        f"/api/v1/events/{event_id}",
        f"/api/v1/alerts/{alert_id}",
        f"/api/v1/incidents/{incident_id}",
    ):
        r = client.get(path, headers=other)
        assert r.status_code == 404, path
    for path in (
        "/api/v1/events",
        "/api/v1/alerts",
        "/api/v1/incidents",
        "/api/v1/events?event_type=login_failure",
        "/api/v1/alerts?severity=high",
        "/api/v1/incidents?status=new",
    ):
        page = client.get(path, headers=other).json()
        assert page["total"] == 0 and page["items"] == [], path
    r = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=other,
        json={"status": "investigating", "version": 1, "reason": "cross-tenant"},
    )
    assert r.status_code == 404


def test_rls_blocks_runtime_role_without_or_with_wrong_tenant(
    client: Any, db_env: dict[str, str]
) -> None:
    _seed_incident(client)
    eng = app_engine(db_env)
    with eng.begin() as c:
        assert c.execute(text("SELECT count(*) FROM security_events")).scalar_one() == 0
        c.execute(text("SELECT set_config('aegis.tenant_id', 'tenant_other', true)"))
        for table in ("security_events", "detection_alerts", "incidents", "alert_events"):
            assert c.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0  # noqa: S608
    with eng.begin() as c:
        c.execute(text("SELECT set_config('aegis.tenant_id', 'tenant_demo', true)"))
        assert c.execute(text("SELECT count(*) FROM security_events")).scalar_one() == 12
    # Writing a row for another tenant is refused by the WITH CHECK policy.
    with eng.begin() as c:
        c.execute(text("SELECT set_config('aegis.tenant_id', 'tenant_other', true)"))
        try:
            c.execute(
                text(
                    "INSERT INTO incidents (id, tenant_id, title, status, severity, "
                    "priority, correlation_rule, correlation_key, origin, "
                    "last_activity_at) VALUES ('inc_x','tenant_demo','x','new','low',"
                    "'P4','r','k','synthetic', now())"
                )
            )
            raise AssertionError("cross-tenant insert was allowed")
        except ProgrammingError as exc:
            assert "row-level security" in str(exc)
    eng.dispose()


def test_tenant_claim_in_payload_is_rejected(client: Any) -> None:
    h = login(client)
    ev = fixture_events()[0] | {"tenant_id": "tenant_other"}
    r = client.post("/api/v1/events", json={"events": [ev]}, headers=h)
    assert r.status_code == 422
    assert r.json()["results"][0]["status"] == "rejected"
    assert r.json()["results"][0]["errors"][0]["field"] == "tenant_id"


# ---- Authentication -----------------------------------------------------------------------


def test_requests_without_valid_token_are_rejected(client: Any, db_env: dict[str, str]) -> None:
    assert client.get("/api/v1/incidents").status_code == 401
    bad = {"Authorization": "Bearer not-a-token"}
    assert client.get("/api/v1/incidents", headers=bad).status_code == 401
    none_alg = jwt.encode(
        {"sub": "user:x", "tid": "tenant_demo", "roles": ["analyst"]}, key="", algorithm="none"
    )
    assert (
        client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {none_alg}"}).status_code
        == 401
    )
    now = int(time.time())
    expired = jwt.encode(
        {
            "iss": "aegis-local",
            "aud": "aegis-api",
            "sub": "user:x",
            "tid": "tenant_demo",
            "roles": ["analyst"],
            "jti": "x",
            "iat": now - 7200,
            "nbf": now - 7200,
            "exp": now - 3600,
        },
        db_env["AEGIS_JWT_SECRET"],
        algorithm="HS256",
    )
    r = client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401 and r.json()["error"]["code"] == "invalid_token"
    forged = jwt.encode(
        {
            "iss": "aegis-local",
            "aud": "aegis-api",
            "sub": "user:x",
            "tid": "tenant_demo",
            "roles": ["analyst"],
            "jti": "y",
            "iat": now,
            "nbf": now,
            "exp": now + 60,
        },
        "attacker-chosen-secret-that-is-long-enough",
        algorithm="HS256",
    )
    assert (
        client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {forged}"}).status_code
        == 401
    )


def test_logout_revokes_token(client: Any) -> None:
    h = login(client)
    assert client.get("/api/v1/auth/me", headers=h).status_code == 200
    assert client.post("/api/v1/auth/logout", headers=h).status_code == 204
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401


def test_repeated_login_failures_are_throttled_and_audited(
    client: Any, db_env: dict[str, str]
) -> None:
    for _ in range(5):
        r = client.post(
            "/api/v1/auth/login",
            json={"username": "viewer@demo.local", "password": "wrong-password"},
        )
        assert r.status_code == 401
        assert "wrong-password" not in r.text
    r = client.post(
        "/api/v1/auth/login", json={"username": "viewer@demo.local", "password": DEV_PASSWORD}
    )
    assert r.status_code == 429
    # Unknown user gets the same response as a wrong password (no user enumeration).
    r = client.post("/api/v1/auth/login", json={"username": "nobody@x", "password": "nope"})
    assert r.status_code == 401 and r.json()["error"]["code"] == "invalid_credentials"
    eng = owner_engine(db_env)
    with eng.connect() as c:
        outcomes = [
            row[0]
            for row in c.execute(
                text("SELECT outcome FROM audit_logs WHERE action='auth.login' ORDER BY id")
            )
        ]
    eng.dispose()
    assert outcomes.count("denied") == 6 and outcomes.count("throttled") == 1


# ---- Authorization (capability matrix) ----------------------------------------------------


def test_capabilities_are_enforced_server_side(client: Any) -> None:
    _, _, _, incident_id = _seed_incident(client)
    viewer = login(client, "viewer@demo.local")
    auditor = login(client, "auditor@demo.local")
    admin = login(client, "admin@demo.local")
    assert client.get(f"/api/v1/incidents/{incident_id}", headers=viewer).status_code == 200
    r = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=viewer,
        json={"status": "investigating", "version": 1, "reason": "try"},
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"
    assert (
        client.post(
            "/api/v1/events", json={"events": fixture_events()[:1]}, headers=viewer
        ).status_code
        == 403
    )
    assert client.get("/api/v1/events", headers=auditor).status_code == 403
    assert client.get("/api/v1/audit", headers=viewer).status_code == 403
    audit = client.get("/api/v1/audit", headers=admin).json()
    assert audit["total"] > 0
    assert {a["action"] for a in audit["items"]} >= {"events.ingest", "auth.login"}


# ---- Input hardening ----------------------------------------------------------------------


def test_malformed_oversized_and_partial_batches(client: Any) -> None:
    h = login(client)
    r = client.post(
        "/api/v1/events", content=b"{not json", headers={**h, "Content-Type": "application/json"}
    )
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_failed"

    huge = b"{" + b" " * (1_048_576 + 10) + b"}"
    r = client.post(
        "/api/v1/events", content=huge, headers={**h, "Content-Type": "application/json"}
    )
    assert r.status_code == 413

    many = [fixture_events()[0]] * 501
    assert client.post("/api/v1/events", json={"events": many}, headers=h).status_code == 413

    gz = gzip.compress(json.dumps({"events": fixture_events()}).encode())
    r = client.post(
        "/api/v1/events",
        content=gz,
        headers={**h, "Content-Type": "application/json", "Content-Encoding": "gzip"},
    )
    assert r.status_code == 415

    good = fixture_events()[0]
    bad_version = fixture_events()[1] | {"schema_version": "9.9"}
    naive_time = fixture_events()[2] | {"observed_at": "2026-01-01T09:00:00"}
    future = fixture_events()[3] | {"observed_at": "2999-01-01T00:00:00Z"}
    bad_ip = fixture_events()[4] | {"source_ip": "not-an-ip"}
    r = client.post(
        "/api/v1/events",
        json={"events": [good, bad_version, naive_time, future, bad_ip]},
        headers=h,
    )
    assert r.status_code == 207
    statuses = [x["status"] for x in r.json()["results"]]
    assert statuses == ["accepted", "rejected", "rejected", "rejected", "rejected"]
    # Rejected item errors never echo submitted values.
    assert "not-an-ip" not in r.text


def test_error_responses_are_structured_and_safe(client: Any) -> None:
    h = login(client)
    r = client.get("/api/v1/incidents/inc_does_not_exist", headers=h)
    body = r.json()["error"]
    assert r.status_code == 404 and body["code"] == "not_found" and body["correlation_id"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    r = client.get("/api/v1/events?cursor=%%%garbage", headers=h)
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_cursor"


def test_audit_log_and_events_are_append_only_for_runtime_role(db_env: dict[str, str]) -> None:
    eng = app_engine(db_env)
    for stmt in (
        "UPDATE audit_logs SET outcome='x'",
        "DELETE FROM audit_logs",
        "UPDATE security_events SET event_type='x'",
        "DELETE FROM security_events",
        "DELETE FROM detection_rules",
    ):
        with eng.begin() as c:
            try:
                c.execute(text(stmt))
                raise AssertionError(f"runtime role was allowed: {stmt}")
            except ProgrammingError as exc:
                assert "permission denied" in str(exc)
    # Built-in rules are invisible to UPDATE through RLS, even with a tenant scope set.
    with eng.begin() as c:
        c.execute(text("SELECT set_config('aegis.tenant_id', 'tenant_demo', true)"))
        changed = c.execute(
            text("UPDATE detection_rules SET status='disabled' WHERE tenant_id IS NULL")
        ).rowcount
        assert changed == 0
    eng.dispose()
