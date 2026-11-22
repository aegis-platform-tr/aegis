"""Sweeps every route in the OpenAPI document instead of relying on hand-picked examples:
  1. every non-public route rejects unauthenticated requests;
  2. every route that takes a resource id refuses another tenant's ids;
  3. list routes never return another tenant's records.
New routes are covered automatically, so a forgotten check fails here."""

from __future__ import annotations

import json
import re
from typing import Any

from conftest import fixture_events, login

from aegis.worker import drain

PUBLIC = {
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/ready"),
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/agent/enroll"),
}
AGENT_AUTH = re.compile(r"^/api/v1/agent/")


def _routes(client: Any) -> list[tuple[str, str]]:
    spec = client.get("/api/openapi.json").json()
    return [
        (m.upper(), p)
        for p, ops in spec["paths"].items()
        for m in ops
        if m in ("get", "post", "put", "patch", "delete")
    ]


def test_every_non_public_route_requires_authentication(client: Any) -> None:
    routes = _routes(client)
    assert len(routes) >= 45, "route discovery broke"
    failures = []
    for method, path in routes:
        if (method, path) in PUBLIC:
            continue
        url = re.sub(r"\{[^}]+\}", "x", path)
        r = client.request(method, url, json={})
        if r.status_code != 401:
            failures.append((method, path, r.status_code))
    assert failures == []


def _seed_demo(client: Any) -> dict[str, str]:
    """Creates one of every resource type in tenant_demo and returns their ids."""
    from aegis.cli import _seed_resources

    _seed_resources()
    analyst = login(client)
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=analyst)
    client.post("/api/v1/fixtures/ids-correlation-demo/import", headers=analyst)
    drain()
    inc = client.get("/api/v1/incidents", headers=analyst).json()["items"][0]
    alert = client.get("/api/v1/alerts", headers=analyst).json()["items"][0]
    event = client.get("/api/v1/events", headers=analyst).json()["items"][0]
    admin = login(client, "admin@demo.local")
    tok = client.post(
        "/api/v1/agents/enrollment-tokens", headers=admin, json={"label": "sweep"}
    ).json()["enrollment_token"]
    agent = client.post(
        "/api/v1/agent/enroll",
        json={
            "enrollment_token": tok,
            "hostname": "h1",
            "platform": "linux",
            "agent_version": "0.2.0",
        },
    ).json()
    sup = client.post(
        "/api/v1/suppressions",
        headers=analyst,
        json={
            "entity_field": "source_ip",
            "entity_value": "203.0.113.200",
            "reason": "sweep test",
            "expires_in_hours": 1,
        },
    ).json()
    prop = client.post(
        "/api/v1/responses",
        headers=login(client, "proposer@demo.local"),
        json={
            "resource_id": "res_sim_tenant_demo",
            "cidr": "203.0.113.0/24",
            "minutes": 30,
            "reason": "sweep test",
        },
    ).json()
    client.post(
        "/api/v1/rules",
        headers=admin,
        json={
            "slug": "sweep.rule",
            "name": "Sweep rule",
            "description": "x x x",
            "severity": "low",
            "confidence": 0.5,
            "change_reason": "sweep test",
            "definition": {
                "kind": "threshold",
                "match": {"event_category": "authentication", "event_type": "login_failure"},
                "group_by": ["source_ip"],
                "window_seconds": 60,
                "threshold": 2,
                "time_field": "occurred_at_else_observed_at",
                "late_arrival": "recount_bucket",
            },
        },
    )
    return {
        "incident_id": inc["incident_id"],
        "alert_id": alert["alert_id"],
        "event_id": event["event_id"],
        "agent_id": agent["agent_id"],
        "suppression_id": sup["suppression_id"],
        "proposal_id": prop["proposal_id"],
        "resource_id": "res_sim_tenant_demo",
        "rule_id": "tenant_demo.sweep.rule",
        "revision": "1",
        "service_key": "198.51.100.10:443",
        "name": "auth-bruteforce-demo",
    }


def test_other_tenant_cannot_touch_any_resource_by_id(client: Any) -> None:
    ids = _seed_demo(client)
    # A user in tenant_other holding every role, so failures can only come from tenant scope.
    from aegis.db import session_scope
    from aegis.models import User
    from aegis.security import ROLE_CAPABILITIES, hash_password
    from conftest import DEV_PASSWORD

    with session_scope() as s:
        s.add(
            User(
                username="root@other.local",
                tenant_id="tenant_other",
                roles=list(ROLE_CAPABILITIES),
                password_hash=hash_password(DEV_PASSWORD),
            )
        )
    other = login(client, "root@other.local")
    bodies = {
        "reason": "cross-tenant attempt",
        "status": "investigating",
        "version": 1,
        "body": "x",
        "assignee": None,
        "fixture": "auth-bruteforce-demo",
        "kind": "note",
    }
    leaks = []
    for method, path in _routes(client):
        params = re.findall(r"\{([^}]+)\}", path)
        if not params or path.startswith("/api/v1/fixtures") or AGENT_AUTH.match(path):
            continue
        url = path
        for p in params:
            url = url.replace("{" + p + "}", ids[p])
        headers = other | (
            {"Idempotency-Key": "sweep-key-123"} if path.endswith(("/execute", "/rollback")) else {}
        )
        r = client.request(method, url, headers=headers, json=bodies)
        text = r.text
        if r.status_code < 400 or any(
            v in text for k, v in ids.items() if k.endswith("_id") and len(v) > 12
        ):
            # network minutes for an unknown key legitimately returns an empty 200
            if path.endswith("/minutes") and r.status_code == 200 and not r.json()["minutes"]:
                continue
            leaks.append((method, path, r.status_code, text[:120]))
    assert leaks == []


def test_list_routes_never_include_other_tenant_records(client: Any) -> None:
    ids = _seed_demo(client)
    from aegis.db import session_scope
    from aegis.models import User
    from aegis.security import ROLE_CAPABILITIES, hash_password
    from conftest import DEV_PASSWORD

    with session_scope() as s:
        s.add(
            User(
                username="root2@other.local",
                tenant_id="tenant_other",
                roles=list(ROLE_CAPABILITIES),
                password_hash=hash_password(DEV_PASSWORD),
            )
        )
    other = login(client, "root2@other.local")
    secrets_of_demo = [v for k, v in ids.items() if k.endswith("_id") and len(v) > 12]
    checked = 0
    for method, path in _routes(client):
        if method != "GET" or "{" in path or (method, path) in PUBLIC:
            continue
        r = client.get(path, headers=other)
        checked += 1
        assert r.status_code in (200, 403), (path, r.status_code)
        body = json.dumps(r.json())
        assert not any(v in body for v in secrets_of_demo), path
        assert "tenant_demo" not in body or path == "/api/v1/rules", path
    assert checked >= 15
