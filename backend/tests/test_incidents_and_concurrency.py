"""Incident lifecycle, optimistic concurrency and concurrent ingest/processing."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from conftest import fixture_events, login, owner_engine
from sqlalchemy import text

from aegis.db import session_scope
from aegis.ingestion import ingest_items
from aegis.worker import drain


def _incident(client: Any) -> tuple[dict[str, str], dict[str, Any]]:
    h = login(client)
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=h)
    drain()
    inc = client.get("/api/v1/incidents", headers=h).json()["items"][0]
    return h, inc


def test_transitions_history_and_reopen(client: Any) -> None:
    h, inc = _incident(client)
    url = f"/api/v1/incidents/{inc['incident_id']}"
    r = client.patch(
        url, headers=h, json={"status": "investigating", "version": 1, "reason": "triage started"}
    )
    assert r.status_code == 200 and r.json()["version"] == 2
    r = client.patch(
        url, headers=h, json={"status": "closed", "version": 2, "reason": "synthetic exercise"}
    )
    assert r.status_code == 200
    r = client.patch(url, headers=h, json={"status": "contained", "version": 3, "reason": "x-y"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "invalid_transition"
    r = client.patch(
        url,
        headers=h,
        json={"status": "investigating", "version": 3, "reason": "reopened: new evidence"},
    )
    assert r.status_code == 200 and r.json()["status"] == "investigating"
    transitions = [t for t in r.json()["timeline"] if t["kind"] == "transition"]
    assert len(transitions) == 4
    assert "reopened: new evidence" in transitions[-1]["summary"]


def test_stale_version_is_rejected(client: Any) -> None:
    h, inc = _incident(client)
    url = f"/api/v1/incidents/{inc['incident_id']}"
    assert (
        client.patch(
            url, headers=h, json={"status": "investigating", "version": 1, "reason": "first"}
        ).status_code
        == 200
    )
    r = client.patch(
        url, headers=h, json={"status": "contained", "version": 1, "reason": "stale writer"}
    )
    assert r.status_code == 409 and r.json()["error"]["code"] == "version_conflict"


def test_parallel_duplicate_submissions_accept_exactly_once(db_env: dict[str, str]) -> None:
    event = fixture_events()[0]

    def submit(_: int) -> str:
        with session_scope(tenant_id="tenant_demo") as s:
            return ingest_items(
                s,
                tenant_id="tenant_demo",
                producer_id="user:parallel",
                items=[event],
                ingest_channel="test",
            )[0].status.value

    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(submit, range(16)))
    assert statuses.count("accepted") == 1 and statuses.count("duplicate") == 15


def test_parallel_workers_create_one_alert_and_one_incident(
    client: Any, db_env: dict[str, str]
) -> None:
    h = login(client)
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=h)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: drain(), range(4)))
    assert sum(r.processed for r in results) == 12
    assert sum(r.failed for r in results) == 0
    eng = owner_engine(db_env)
    with eng.connect() as c:
        assert c.execute(text("SELECT count(*) FROM detection_alerts")).scalar_one() == 1
        assert c.execute(text("SELECT count(*) FROM incidents")).scalar_one() == 1
        assert c.execute(text("SELECT count(*) FROM alert_events")).scalar_one() == 7
    eng.dispose()


def test_pagination_is_stable_and_complete(client: Any) -> None:
    h = login(client)
    client.post("/api/v1/events", json={"events": fixture_events()}, headers=h)
    seen: list[str] = []
    cursor = None
    while True:
        q = "/api/v1/events?limit=5" + (f"&cursor={cursor}" if cursor else "")
        page = client.get(q, headers=h).json()
        seen += [e["event_id"] for e in page["items"]]
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert len(seen) == 12 and len(set(seen)) == 12
