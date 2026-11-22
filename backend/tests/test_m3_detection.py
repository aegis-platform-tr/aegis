"""M3: rule lifecycle, suppressions, multi-source correlation, incident notes/assignment and
service baselines (legitimate spike vs anomalous surge)."""

from __future__ import annotations

import json
from typing import Any

from conftest import REPO, fixture_events, login, owner_engine
from sqlalchemy import text

from aegis.worker import drain

THRESHOLD_DEF = {
    "kind": "threshold",
    "match": {"event_category": "authentication", "event_type": "login_failure"},
    "group_by": ["source_ip"],
    "window_seconds": 3600,
    "threshold": 3,
    "time_field": "occurred_at_else_observed_at",
    "late_arrival": "recount_bucket",
}


def _rule_body(**over: Any) -> dict[str, Any]:
    return {
        "slug": "auth.many-failures",
        "name": "Many failures per source (hourly)",
        "description": "Tenant tuning rule",
        "severity": "medium",
        "confidence": 0.5,
        "definition": THRESHOLD_DEF,
        "change_reason": "initial tuning",
    } | over


def test_rule_lifecycle_test_publish_rollback_and_audit(
    client: Any, db_env: dict[str, str]
) -> None:
    dm = login(client, "admin@demo.local")
    r = client.post("/api/v1/rules", headers=dm, json=_rule_body())
    assert r.status_code == 201, r.text
    rule_id = r.json()["rule_id"]
    assert rule_id == "tenant_demo.auth.many-failures" and r.json()["status"] == "draft"

    # Draft rules can be tested against labeled fixtures without persisting anything.
    t = client.post(
        f"/api/v1/rules/{rule_id}/revisions/1/test",
        headers=dm,
        json={"fixture": "auth-bruteforce-demo"},
    ).json()
    assert t["persisted"] is False and t["would_alert"] == 2  # .42 (7) and .7 (3) in 1 h
    assert client.get("/api/v1/alerts", headers=dm).json()["total"] == 0

    # Drafts do not run in the pipeline.
    analyst = login(client)
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=analyst)
    drain()
    assert {a["rule_id"] for a in client.get("/api/v1/alerts", headers=dm).json()["items"]} == {
        "auth.bruteforce.source_asset"
    }

    v2 = THRESHOLD_DEF | {"threshold": 5}
    r2 = client.post(
        f"/api/v1/rules/{rule_id}/revisions",
        headers=dm,
        json={
            k: v
            for k, v in _rule_body(definition=v2, change_reason="raise threshold").items()
            if k != "slug"
        },
    )
    assert r2.status_code == 201 and r2.json()["revision"] == 2
    assert (
        client.post(
            f"/api/v1/rules/{rule_id}/revisions/1/publish", headers=dm, json={"reason": "go live"}
        ).json()["status"]
        == "active"
    )
    assert (
        client.post(
            f"/api/v1/rules/{rule_id}/revisions/2/publish", headers=dm, json={"reason": "tighten"}
        ).status_code
        == 200
    )
    rb = client.post(
        f"/api/v1/rules/{rule_id}/revisions/1/publish",
        headers=dm,
        json={"reason": "rollback: too quiet"},
    )
    assert rb.status_code == 200
    states = {
        (x["revision"], x["status"])
        for x in client.get("/api/v1/rules", headers=dm).json()
        if x["rule_id"] == rule_id
    }
    assert states == {(1, "active"), (2, "retired")}
    eng = owner_engine(db_env)
    with eng.connect() as c:
        actions = [
            r[0]
            for r in c.execute(
                text("SELECT action FROM audit_logs WHERE target_type='rule' ORDER BY id")
            )
        ]
    eng.dispose()
    assert actions == [
        "rule.create",
        "rule.revise",
        "rule.publish",
        "rule.publish",
        "rule.rollback",
    ]


def test_rule_validation_and_permissions(client: Any) -> None:
    dm = login(client, "admin@demo.local")
    for bad in (
        {"kind": "script", "code": "import os"},
        THRESHOLD_DEF | {"exec": "curl http://x"},
        THRESHOLD_DEF | {"group_by": ["attributes.__class__"]},
        THRESHOLD_DEF | {"window_seconds": 1},
    ):
        r = client.post("/api/v1/rules", headers=dm, json=_rule_body(definition=bad))
        assert r.status_code == 422, bad
        assert r.json()["error"]["code"] == "invalid_rule_definition"
    assert client.post("/api/v1/rules", headers=login(client), json=_rule_body()).status_code == 403
    # Built-ins are immutable; other tenants never see tenant rules.
    r = client.post(
        "/api/v1/rules/auth.bruteforce.source_asset/revisions",
        headers=dm,
        json={k: v for k, v in _rule_body().items() if k != "slug"},
    )
    assert r.status_code == 403
    client.post("/api/v1/rules", headers=dm, json=_rule_body())
    other = client.get("/api/v1/rules", headers=login(client, "analyst@other.local")).json()
    assert all(x["scope"] == "built-in" for x in other)


def test_tenant_can_disable_builtin_rule_for_itself_only(client: Any) -> None:
    dm = login(client, "admin@demo.local")
    client.post(
        "/api/v1/rules/auth.bruteforce.source_asset/disable",
        headers=dm,
        json={"reason": "noisy in lab"},
    )
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=login(client))
    drain()
    assert client.get("/api/v1/alerts", headers=dm).json()["total"] == 0
    other = login(client, "analyst@other.local")
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=other)
    drain()
    assert client.get("/api/v1/alerts", headers=other).json()["total"] == 1


def test_suppression_keeps_evidence_but_skips_incident(client: Any) -> None:
    analyst = login(client)
    r = client.post(
        "/api/v1/suppressions",
        headers=analyst,
        json={
            "entity_field": "source_ip",
            "entity_value": "192.0.2.42",
            "reason": "authorized red-team exercise (synthetic)",
            "expires_in_hours": 4,
        },
    )
    assert r.status_code == 201 and r.json()["state"] == "active"
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=analyst)
    drain()
    alert = client.get("/api/v1/alerts", headers=analyst).json()["items"][0]
    assert alert["suppressed"] is True and "Suppressed by" in alert["explanation"]
    assert (
        len(client.get(f"/api/v1/alerts/{alert['alert_id']}", headers=analyst).json()["event_ids"])
        == 7
    )
    assert client.get("/api/v1/incidents", headers=analyst).json()["total"] == 0
    assert (
        client.get("/api/v1/suppressions", headers=login(client, "analyst@other.local")).json()
        == []
    )


def test_multi_source_correlation_joins_existing_incident(client: Any) -> None:
    h = login(client)
    client.post("/api/v1/fixtures/auth-bruteforce-demo/import", headers=h)
    client.post("/api/v1/fixtures/ids-correlation-demo/import", headers=h)
    drain()
    alerts = client.get("/api/v1/alerts", headers=h).json()["items"]
    assert {a["rule_id"] for a in alerts} == {
        "auth.bruteforce.source_asset",
        "ids.suricata.high_severity",
        "auth.windows.account_lockout",
    }
    incidents = client.get("/api/v1/incidents", headers=h).json()["items"]
    assert len(incidents) == 2
    brute = next(i for i in incidents if i["correlation_key"] == "source_ip:192.0.2.42")
    assert brute["alert_count"] == 2  # auth burst + IDS alert, one incident


def test_notes_assignment_and_closure_reason_in_timeline(client: Any) -> None:
    h = login(client)
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=h)
    drain()
    inc = client.get("/api/v1/incidents", headers=h).json()["items"][0]
    url = f"/api/v1/incidents/{inc['incident_id']}"
    r = client.post(
        url + "/assign", headers=h, json={"assignee": "analyst@demo.local", "version": 1}
    )
    assert r.status_code == 200 and r.json()["assigned_to"] == "analyst@demo.local"
    assert (
        client.post(
            url + "/assign", headers=h, json={"assignee": "analyst@other.local", "version": 2}
        ).status_code
        == 422
    )
    assert (
        client.post(url + "/assign", headers=h, json={"assignee": None, "version": 1}).status_code
        == 409
    )
    client.post(url + "/notes", headers=h, json={"body": "Blocked 192.0.2.42 at the edge (lab)."})
    client.post(
        url + "/notes",
        headers=h,
        json={"kind": "containment_verification", "body": "No further failures after 09:14."},
    )
    d = client.post(
        url + "/notes", headers=h, json={"kind": "closure_reason", "body": "Synthetic exercise."}
    ).json()
    kinds = [t["summary"].split("]")[0] for t in d["timeline"] if t["kind"] == "note"]
    assert kinds == ["[assignment", "[note", "[containment_verification", "[closure_reason"]
    viewer = login(client, "viewer@demo.local")
    assert client.post(url + "/notes", headers=viewer, json={"body": "x"}).status_code == 403


def test_ddos_baseline_separates_legitimate_spike_from_anomaly(client: Any) -> None:
    h = login(client)
    r = client.post("/api/v1/fixtures/ddos-baseline-demo/import", headers=h).json()
    assert r["accepted"] == 2879 and r["rejected"] == 0
    stats = drain()
    assert stats.failed == 0
    svc = client.get("/api/v1/network/services", headers=h).json()
    assert [s["service_key"] for s in svc] == ["198.51.100.10:443"]
    minutes = client.get("/api/v1/network/services/198.51.100.10:443/minutes", headers=h).json()[
        "minutes"
    ]
    by_min = {m["minute"][11:16]: m["classification"] for m in minutes}
    assert all(by_min[f"10:{m:02d}"] == "warming_up" for m in range(0, 15))
    assert [by_min[f"10:{m}"] for m in (40, 41, 42)] == ["expected_burst"] * 3
    assert [by_min[f"10:{m}"] for m in (50, 51, 52)] == ["anomaly"] * 3
    normal = [k for k, v in by_min.items() if v == "normal"]
    assert len(normal) >= 30
    alerts = client.get("/api/v1/alerts", headers=h).json()["items"]
    assert len(alerts) == 1  # one alert spanning the 3 anomalous minutes
    a = alerts[0]
    assert a["rule_id"] == "ddos.service_baseline" and a["evidence_quality"] == "aggregate"
    assert a["window_start"].startswith("2026-01-02T10:50") and a["window_end"].startswith(
        "2026-01-02T10:53"
    )
    assert "pending corroboration" in a["explanation"]
    inc = client.get("/api/v1/incidents", headers=h).json()["items"]
    assert len(inc) == 1 and inc[0]["correlation_key"] == "service:198.51.100.10:443"
    # False-positive accounting on the labeled burst: 0 alerts over 3 burst minutes.
    burst_alerts = [
        m for m in minutes if m["minute"][11:16] in ("10:40", "10:41", "10:42") and m["alert_id"]
    ]
    assert burst_alerts == []


def test_fixture_metadata_matches_expectations() -> None:
    pack = json.loads((REPO / "sample_data/fixtures/ddos-baseline-demo.json").read_text())
    assert pack["origin"] == "synthetic" and pack["generator"]["seed"] == 20260102
    assert all(e["origin"] == "synthetic" for e in pack["events"])
