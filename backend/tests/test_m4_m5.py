"""M4 (AI gateway) and M5 (response transactions)."""

from __future__ import annotations

import subprocess
import threading
from typing import Any

import pytest
from conftest import fixture_events, login, owner_engine
from sqlalchemy import text

from aegis.ai import evaluate
from aegis.worker import drain

RES = "res_sim_tenant_demo"


def _incident(client: Any) -> str:
    h = login(client)
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=h)
    drain()
    return str(client.get("/api/v1/incidents", headers=h).json()["items"][0]["incident_id"])


def _other_event(client: Any) -> str:
    h = login(client, "analyst@other.local")
    r = client.post("/api/v1/events", json={"events": fixture_events()[:1]}, headers=h)
    return str(r.json()["results"][0]["event_id"])


@pytest.fixture()
def seeded_resource(db_env: dict[str, str]) -> None:
    from aegis.cli import _seed_resources

    _seed_resources()


# ---- M4 ---------------------------------------------------------------------------------


def test_ai_evaluation_set_has_no_unexpected_failures(client: Any, seeded_resource: None) -> None:
    inc = _incident(client)
    results = evaluate.run(client, lambda u: login(client, u), inc, _other_event(client))
    failures = [(r["id"], r["mismatches"]) for r in results if r["status"] == "fail"]
    assert failures == [], failures
    assert sum(r["status"] == "known_deviation" for r in results) == 3


def test_ai_audit_records_are_redacted_and_tenant_scoped(
    client: Any, db_env: dict[str, str]
) -> None:
    h = login(client)
    r = client.post(
        "/api/v1/ai/requests",
        headers=h,
        json={"capability": "ask", "prompt": f"leaked password={evaluate.CANARY_PW} here"},
    )
    assert r.status_code == 200 and r.json()["decision"] == "redact"
    eng = owner_engine(db_env)
    with eng.connect() as c:
        dump = c.execute(text("SELECT row_to_json(a)::text FROM ai_requests a")).scalars().all()
        audit_dump = c.execute(text("SELECT details::text FROM audit_logs")).scalars().all()
    eng.dispose()
    assert dump and all(evaluate.CANARY_PW not in d for d in dump + audit_dump)
    rows = client.get("/api/v1/ai/requests", headers=login(client, "admin@demo.local")).json()
    assert rows[0]["prompt_chars"] > 0 and len(rows[0]["prompt_sha256"]) == 64
    assert (
        client.get("/api/v1/ai/requests", headers=login(client, "analyst@other.local")).status_code
        == 403
    )
    other_admin_view = client.get("/api/v1/ai/requests", headers=h)
    assert other_admin_view.status_code == 403  # analysts lack ai:audit


def test_ai_cannot_summarize_other_tenants_incident(client: Any) -> None:
    inc = _incident(client)
    r = client.post(
        "/api/v1/ai/requests",
        headers=login(client, "analyst@other.local"),
        json={"capability": "summarize_incident", "incident_id": inc},
    )
    assert r.status_code == 404


def test_pipeline_unaffected_when_provider_fails(client: Any) -> None:
    h = login(client)
    r = client.post(
        "/api/v1/ai/requests", headers=h, json={"capability": "ask", "prompt": "x [[mock:outage]]"}
    )
    assert r.json()["decision"] == "dependency_unavailable"
    assert client.get("/api/v1/ready").status_code == 200
    _incident(client)
    assert client.get("/api/v1/incidents", headers=h).json()["total"] == 1


# ---- M5 ---------------------------------------------------------------------------------


def _propose(
    client: Any,
    cidr: str = "203.0.113.0/24",
    user: str = "proposer@demo.local",
    resource: str = RES,
) -> dict[str, Any]:
    r = client.post(
        "/api/v1/responses",
        headers=login(client, user),
        json={"resource_id": resource, "cidr": cidr, "minutes": 60, "reason": "contain source"},
    )
    assert r.status_code == 201, r.text
    return dict(r.json())


def _approve_flow(client: Any, cidr: str = "203.0.113.0/24") -> str:
    p = _propose(client, cidr)
    pv = client.post(
        f"/api/v1/responses/{p['proposal_id']}/preview",
        headers=login(client, "proposer@demo.local"),
    ).json()
    assert pv["status"] == "approval_pending", pv
    a = client.post(
        f"/api/v1/responses/{p['proposal_id']}/approve",
        headers=login(client, "approver@demo.local"),
        json={"reason": "approved in lab"},
    )
    assert a.status_code == 200 and a.json()["status"] == "approved", a.text
    return str(p["proposal_id"])


def _resource(client: Any) -> dict[str, Any]:
    rows = client.get("/api/v1/response/resources", headers=login(client, "approver@demo.local"))
    return next(r for r in rows.json() if r["resource_id"] == RES)


def test_full_lifecycle_idempotent_execute_and_rollback(
    client: Any, seeded_resource: None, monkeypatch: Any
) -> None:
    def no_host_changes(*a: Any, **k: Any) -> None:
        raise AssertionError("response path attempted to run a host command")

    monkeypatch.setattr(subprocess, "run", no_host_changes)
    monkeypatch.setattr(subprocess, "Popen", no_host_changes)
    p = _propose(client)
    assert p["status"] == "proposed" and p["diff"]["add"][0]["cidr"] == "203.0.113.0/24"
    pv = client.post(
        f"/api/v1/responses/{p['proposal_id']}/preview",
        headers=login(client, "proposer@demo.local"),
    ).json()
    prev = pv["preview"]
    assert prev["coverage"] == "known" and prev["automatic_apply_allowed"] is True
    assert prev["host_state"].startswith("unchanged") and prev["addresses_affected"] == 256
    approver = login(client, "approver@demo.local")
    client.post(
        f"/api/v1/responses/{p['proposal_id']}/approve",
        headers=approver,
        json={"reason": "approved for lab"},
    )
    ex = client.post(
        f"/api/v1/responses/{p['proposal_id']}/execute",
        headers=approver | {"Idempotency-Key": "exec-key-0001"},
    )
    assert ex.status_code == 200 and ex.json()["status"] == "verified", ex.text
    assert ex.json()["executions"][0]["verification"]["management_path_reachable"] is True
    again = client.post(
        f"/api/v1/responses/{p['proposal_id']}/execute",
        headers=approver | {"Idempotency-Key": "exec-key-0001"},
    ).json()
    assert again["replayed"] is True and len(_resource(client)["policy_snapshot"]["rules"]) == 1
    dup = client.post(
        f"/api/v1/responses/{p['proposal_id']}/execute",
        headers=approver | {"Idempotency-Key": "exec-key-0002"},
    )
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "already_executed"
    rb = client.post(
        f"/api/v1/responses/{p['proposal_id']}/rollback",
        headers=approver | {"Idempotency-Key": "rollback-0001"},
        json={"reason": "exercise over"},
    )
    assert rb.json()["status"] == "rolled_back"
    assert _resource(client)["policy_snapshot"]["rules"] == []


def test_self_approval_and_missing_idempotency_key_refused(
    client: Any, seeded_resource: None
) -> None:
    p = _propose(client, user="lead@demo.local")
    lead = login(client, "lead@demo.local")
    client.post(f"/api/v1/responses/{p['proposal_id']}/preview", headers=lead)
    r = client.post(
        f"/api/v1/responses/{p['proposal_id']}/approve",
        headers=lead,
        json={"reason": "my own proposal"},
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == "self_approval"
    assert (
        client.post(
            f"/api/v1/responses/{p['proposal_id']}/approve",
            headers=login(client, "proposer@demo.local"),
            json={"reason": "try approve"},
        ).status_code
        == 403
    )  # lacks responses:approve
    pid = _approve_flow(client)
    r = client.post(
        f"/api/v1/responses/{pid}/execute", headers=login(client, "approver@demo.local")
    )
    assert r.status_code == 422  # Idempotency-Key header is required


def test_expired_approval_is_refused_and_recorded(
    client: Any, seeded_resource: None, db_env: dict[str, str]
) -> None:
    pid = _approve_flow(client)
    eng = owner_engine(db_env)
    with eng.begin() as c:
        c.execute(text("UPDATE response_approvals SET expires_at = now() - interval '1 minute'"))
    eng.dispose()
    r = client.post(
        f"/api/v1/responses/{pid}/execute",
        headers=login(client, "approver@demo.local") | {"Idempotency-Key": "k-exp-01"},
    )
    assert r.status_code == 409 and "approval_unexpired" in r.json()["error"]["message"]
    got = client.get(f"/api/v1/responses/{pid}", headers=login(client, "approver@demo.local"))
    assert got.json()["status"] == "expired"
    assert _resource(client)["policy_snapshot"]["rules"] == []


def test_changed_policy_invalidates_pending_execution(client: Any, seeded_resource: None) -> None:
    first = _approve_flow(client, "203.0.113.0/24")
    second = _approve_flow(client, "198.18.0.0/24")
    approver = login(client, "approver@demo.local")
    assert (
        client.post(
            f"/api/v1/responses/{second}/execute",
            headers=approver | {"Idempotency-Key": "k-second-1"},
        ).json()["status"]
        == "verified"
    )
    r = client.post(
        f"/api/v1/responses/{first}/execute", headers=approver | {"Idempotency-Key": "k-first-01"}
    )
    assert r.status_code == 409 and "policy_unchanged" in r.json()["error"]["message"]
    assert (
        client.get(f"/api/v1/responses/{first}", headers=approver).json()["status"] == "invalidated"
    )


def test_protected_path_and_scope_safeguards(client: Any, seeded_resource: None) -> None:
    p = _propose(client, "192.0.2.250/32")
    pv = client.post(
        f"/api/v1/responses/{p['proposal_id']}/preview",
        headers=login(client, "proposer@demo.local"),
    ).json()
    assert pv["preview"]["protected_path_conflicts"] == ["192.0.2.250/32"]
    r = client.post(
        f"/api/v1/responses/{p['proposal_id']}/approve",
        headers=login(client, "approver@demo.local"),
        json={"reason": "try approve"},
    )
    assert r.status_code == 409 and r.json()["error"]["code"] == "protected_conflict"
    for bad in ("10.0.0.0/8", "0.0.0.0/0", "127.0.0.1/32", "203.0.113.1/24", "not-a-cidr"):
        r = client.post(
            "/api/v1/responses",
            headers=login(client, "proposer@demo.local"),
            json={"resource_id": RES, "cidr": bad, "minutes": 60, "reason": "x-y"},
        )
        assert r.status_code == 422, bad


@pytest.mark.parametrize(
    "mode,expected",
    [("apply_error", "failed"), ("verify_error", "rolled_back"), ("unknown_result", "partial")],
)
def test_partial_failures(
    client: Any, seeded_resource: None, db_env: dict[str, str], mode: str, expected: str
) -> None:
    eng = owner_engine(db_env)
    with eng.begin() as c:
        c.execute(text("UPDATE managed_resources SET test_fail_mode = :m"), {"m": mode})
    pid = _approve_flow(client)
    r = client.post(
        f"/api/v1/responses/{pid}/execute",
        headers=login(client, "approver@demo.local") | {"Idempotency-Key": f"k-{mode}"},
    )
    body = r.json()
    assert body["status"] == expected, body
    rules = _resource(client)["policy_snapshot"]["rules"]
    if expected in ("failed", "rolled_back"):
        assert rules == []  # state unchanged or restored
    else:
        assert len(rules) == 1 and "Human recovery" in body["status_reason"]
    with eng.begin() as c:
        c.execute(text("UPDATE managed_resources SET test_fail_mode = NULL"))
    eng.dispose()


def test_concurrent_execute_applies_once(client: Any, seeded_resource: None) -> None:
    pid = _approve_flow(client)
    approver = login(client, "approver@demo.local")
    codes: list[int] = []

    def go(key: str) -> None:
        codes.append(
            client.post(
                f"/api/v1/responses/{pid}/execute", headers=approver | {"Idempotency-Key": key}
            ).status_code
        )

    threads = [threading.Thread(target=go, args=(f"race-key-{i:02d}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(codes) == [200, 409, 409, 409]
    assert len(_resource(client)["policy_snapshot"]["rules"]) == 1


def test_dry_run_adapter_renders_but_refuses_apply(client: Any, seeded_resource: None) -> None:
    admin = login(client, "admin@demo.local")
    r = client.post(
        "/api/v1/response/resources",
        headers=admin,
        json={
            "name": "edge-nft",
            "adapter": "nftables",
            "interface": "eth1",
            "protected_cidrs": ["198.51.100.0/28"],
        },
    )
    assert r.status_code == 201 and r.json()["live_writes_enabled"] is False
    p = _propose(client, resource=r.json()["resource_id"])
    pv = client.post(
        f"/api/v1/responses/{p['proposal_id']}/preview",
        headers=login(client, "proposer@demo.local"),
    ).json()["preview"]
    assert pv["coverage"] == "unknown" and pv["automatic_apply_allowed"] is False
    assert pv["rendered_change"]["text"].startswith(
        "add element inet aegis blocklist_v4 { 203.0.113.0/24 timeout 60m }"
    )
    r = client.post(
        f"/api/v1/responses/{p['proposal_id']}/approve",
        headers=login(client, "approver@demo.local"),
        json={"reason": "try approve"},
    )
    assert r.status_code == 409 and r.json()["error"]["code"] == "unknown_impact"


def test_responses_are_tenant_isolated_and_audited(
    client: Any, seeded_resource: None, db_env: dict[str, str]
) -> None:
    pid = _approve_flow(client)
    other = login(client, "analyst@other.local")
    assert client.get(f"/api/v1/responses/{pid}", headers=other).status_code == 404
    assert client.get("/api/v1/responses", headers=other).json() == []
    eng = owner_engine(db_env)
    with eng.connect() as c:
        acts = [
            r[0]
            for r in c.execute(
                text("SELECT action FROM audit_logs WHERE action LIKE 'response.%' ORDER BY id")
            )
        ]
    eng.dispose()
    assert acts == ["response.propose", "response.preview", "response.approve"]
