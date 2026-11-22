"""M1 acceptance: authenticated ingest -> normalize/persist -> rule -> alert -> incident ->
timeline, plus replay stability and redaction."""

from __future__ import annotations

import copy
import logging
from typing import Any

from conftest import fixture_events, login, owner_engine
from sqlalchemy import text

from aegis.worker import drain

BRUTE_SRC = "192.0.2.42"
CANARY = "AEGIS-CANARY-NOT-A-REAL-SECRET"


def _counts(db_env: dict[str, str]) -> dict[str, int]:
    eng = owner_engine(db_env)
    with eng.connect() as c:
        out = {
            t: c.execute(text(f"SELECT count(*) FROM {t}")).scalar_one()  # noqa: S608
            for t in (
                "security_events",
                "detection_alerts",
                "alert_events",
                "incidents",
                "incident_alerts",
            )
        }
    eng.dispose()
    return out


def test_end_to_end_fixture_creates_one_alert_and_incident(
    client: Any, db_env: dict[str, str]
) -> None:
    h = login(client)
    r = client.post("/api/v1/events", json={"events": fixture_events()}, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["accepted"], body["duplicate"], body["rejected"]) == (12, 0, 0)

    stats = drain()
    assert (stats.processed, stats.failed) == (12, 0)

    alerts = client.get("/api/v1/alerts", headers=h).json()
    assert alerts["total"] == 1
    alert = alerts["items"][0]
    assert alert["rule_id"] == "auth.bruteforce.source_asset"
    assert alert["group_key"] == {"source_ip": BRUTE_SRC, "asset_id": "asset_demo_web01"}
    assert alert["event_count"] == 7
    assert alert["origin"] == "synthetic"

    incidents = client.get("/api/v1/incidents", headers=h).json()
    assert incidents["total"] == 1
    inc_id = incidents["items"][0]["incident_id"]
    assert alert["incident_id"] == inc_id

    detail = client.get(f"/api/v1/incidents/{inc_id}", headers=h).json()
    kinds = [t["kind"] for t in detail["timeline"]]
    assert (
        kinds.count("event") == 7 and kinds.count("alert") == 1 and kinds.count("transition") == 1
    )
    first_event = next(t for t in detail["timeline"] if t["kind"] == "event")
    # Source, collector and server times are kept distinct.
    assert set(first_event["times"]) == {"occurred_at", "observed_at", "ingested_at"}
    assert first_event["times"]["occurred_at"] != first_event["times"]["ingested_at"]
    assert first_event["at"].endswith("Z") or first_event["at"].endswith("+00:00")

    # Follow evidence from the alert back to an underlying event.
    alert_detail = client.get(f"/api/v1/alerts/{alert['alert_id']}", headers=h).json()
    assert len(alert_detail["event_ids"]) == 7
    ev = client.get(f"/api/v1/events/{alert_detail['event_ids'][0]}", headers=h).json()
    assert ev["source_ip"] == BRUTE_SRC and ev["origin"] == "synthetic"


def test_benign_below_threshold_source_does_not_alert(client: Any, db_env: dict[str, str]) -> None:
    h = login(client)
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=h)
    drain()
    alerts = client.get("/api/v1/alerts", headers=h).json()["items"]
    assert all(a["group_key"]["source_ip"] != "198.51.100.7" for a in alerts)


def test_replay_and_worker_restart_keep_logical_counts_stable(
    client: Any, db_env: dict[str, str]
) -> None:
    h = login(client)
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=h)
    drain()
    before = _counts(db_env)

    r = client.post("/api/v1/events", json={"events": fixture_events()}, headers=h)
    body = r.json()
    assert (body["accepted"], body["duplicate"]) == (0, 12)
    # Replay returns the original event ids.
    assert all(item["event_id"] and item["event_id"].startswith("evt_") for item in body["results"])
    assert drain().processed == 0  # "restart": a fresh drain finds no work
    assert _counts(db_env) == before
    assert before["security_events"] == 12 and before["detection_alerts"] == 1


def test_fixture_import_endpoint_uses_same_pipeline_and_is_idempotent(
    client: Any, db_env: dict[str, str]
) -> None:
    h = login(client)
    packs = client.get("/api/v1/fixtures", headers=h).json()
    assert [p["name"] for p in packs] == ["auth-bruteforce-demo"]
    assert packs[0]["origin"] == "synthetic"
    first = client.post("/api/v1/fixtures/auth-bruteforce-demo/import", headers=h).json()
    second = client.post("/api/v1/fixtures/auth-bruteforce-demo/import", headers=h).json()
    assert first["accepted"] == 12 and second["duplicate"] == 12
    drain()
    assert client.get("/api/v1/incidents", headers=h).json()["total"] == 1
    assert client.post("/api/v1/fixtures/..%2Fetc/import", headers=h).status_code == 404


def test_late_out_of_order_event_is_counted_into_its_window(
    client: Any, db_env: dict[str, str]
) -> None:
    h = login(client)
    fails = [
        e
        for e in fixture_events()
        if e["source_ip"] == BRUTE_SRC and e["event_type"] == "login_failure"
    ]
    client.post("/api/v1/events", json={"events": fails[:4]}, headers=h)
    drain()
    assert client.get("/api/v1/alerts", headers=h).json()["total"] == 0
    late = copy.deepcopy(fails[0])
    late["source"]["native_id"] = "late-arrival-001"
    late["occurred_at"] = "2026-01-01T09:11:00Z"  # earlier than everything already seen
    client.post("/api/v1/events", json={"events": [late]}, headers=h)
    drain()
    alerts = client.get("/api/v1/alerts", headers=h).json()
    assert alerts["total"] == 1 and alerts["items"][0]["event_count"] == 5


def test_credentials_are_redacted_and_not_logged(
    client: Any, db_env: dict[str, str], caplog: Any
) -> None:
    caplog.set_level(logging.DEBUG)
    h = login(client)
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=h)
    drain()
    eng = owner_engine(db_env)
    with eng.connect() as c:
        stored = c.execute(
            text("SELECT count(*) FROM security_events WHERE attributes::text LIKE :p"),
            {"p": f"%{CANARY}%"},
        ).scalar_one()
        redacted = c.execute(
            text(
                "SELECT count(*) FROM security_events WHERE "
                "provenance->'redacted_fields' ? 'password'"
            )
        ).scalar_one()
        audit_hits = c.execute(
            text("SELECT count(*) FROM audit_logs WHERE details::text LIKE :p"),
            {"p": f"%{CANARY}%"},
        ).scalar_one()
    eng.dispose()
    assert stored == 0 and audit_hits == 0
    assert redacted == 1
    assert CANARY not in caplog.text


def test_worker_crash_mid_processing_rolls_back_and_retries(
    client: Any, db_env: dict[str, str], monkeypatch: Any
) -> None:
    import aegis.worker as worker_mod

    h = login(client)
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=h)
    calls = {"n": 0}
    real = worker_mod.correlate_alert

    def flaky(session: Any, alert_id: str) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise LookupError("simulated crash after alert write")
        return real(session, alert_id)

    monkeypatch.setattr(worker_mod, "correlate_alert", flaky)
    stats = drain()
    assert stats.failed == 1
    eng = owner_engine(db_env)
    with eng.connect() as c:
        retried = c.execute(
            text("SELECT count(*) FROM work_items WHERE attempts = 2 AND status = 'done'")
        ).scalar_one()
        dead = c.execute(
            text("SELECT count(*) FROM work_items WHERE status <> 'done'")
        ).scalar_one()
    eng.dispose()
    assert retried == 1 and dead == 0
    assert client.get("/api/v1/alerts", headers=h).json()["total"] == 1
    assert client.get("/api/v1/incidents", headers=h).json()["total"] == 1
