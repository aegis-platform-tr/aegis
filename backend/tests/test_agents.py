"""M2: agent enrollment, credentials, heartbeats, revocation and a real agent end-to-end run."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from conftest import BACKEND, REPO, login, owner_engine
from sqlalchemy import text

from aegis.worker import drain

AGENT_DIR = REPO / "agent"


def _token(client: Any, user: str = "admin@demo.local") -> str:
    r = client.post(
        "/api/v1/agents/enrollment-tokens",
        headers=login(client, user),
        json={"label": "test", "ttl_minutes": 10},
    )
    assert r.status_code == 201, r.text
    return str(r.json()["enrollment_token"])


def _enroll(client: Any, token: str, host: str = "web01") -> dict[str, Any]:
    r = client.post(
        "/api/v1/agent/enroll",
        json={
            "enrollment_token": token,
            "hostname": host,
            "platform": "linux",
            "agent_version": "0.2.0",
        },
    )
    assert r.status_code == 201, r.text
    return dict(r.json())


def _hb(cred: str) -> dict[str, Any]:
    return {"Authorization": f"Bearer {cred}"}


def _heartbeat_body(**over: Any) -> dict[str, Any]:
    body = {
        "agent_version": "0.2.0",
        "config_version": 1,
        "agent_time": datetime.now(UTC).isoformat(),
        "queue_depth": 3,
        "spool_bytes": 900,
        "spool_full": False,
        "dropped_events": 0,
        "quarantined_lines": 1,
        "sent_events": 10,
        "sources": [
            {
                "name": "auth",
                "type": "linux_auth",
                "status": "ok",
                "lag_seconds": 1.5,
                "cursor_resets": 0,
            }
        ],
    }
    return body | over


def test_enrollment_token_is_single_use_and_tenant_bound(client: Any) -> None:
    token = _token(client)
    agent = _enroll(client, token)
    assert agent["tenant_id"] == "tenant_demo" and agent["credential"].startswith("aegis_agt_")
    r = client.post(
        "/api/v1/agent/enroll",
        json={
            "enrollment_token": token,
            "hostname": "x",
            "platform": "linux",
            "agent_version": "0.2.0",
        },
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "enrollment_denied"
    assert (
        client.post(
            "/api/v1/agent/enroll",
            json={
                "enrollment_token": "aegis_enr_forged-value",
                "hostname": "x",
                "platform": "linux",
                "agent_version": "0.2.0",
            },
        ).status_code
        == 401
    )
    # Only tenant_admin may mint tokens.
    r = client.post(
        "/api/v1/agents/enrollment-tokens",
        headers=login(client, "analyst@demo.local"),
        json={"label": "x"},
    )
    assert r.status_code == 403


def test_expired_enrollment_token_is_refused(client: Any, db_env: dict[str, str]) -> None:
    token = _token(client)
    eng = owner_engine(db_env)
    with eng.begin() as c:
        c.execute(text("UPDATE enrollment_tokens SET expires_at = now() - interval '1 second'"))
    eng.dispose()
    r = client.post(
        "/api/v1/agent/enroll",
        json={
            "enrollment_token": token,
            "hostname": "x",
            "platform": "linux",
            "agent_version": "0.2.0",
        },
    )
    assert r.status_code == 401


def test_agent_events_heartbeat_rotation_and_revocation(client: Any) -> None:
    agent = _enroll(client, _token(client))
    cred = agent["credential"]
    ev = {
        "schema_version": "1.0",
        "event_category": "authentication",
        "event_type": "login_failure",
        "occurred_at": "2026-01-01T09:00:00Z",
        "observed_at": "2026-01-01T09:00:01Z",
        "source": {"adapter": "linux-auth", "adapter_version": "1", "native_id": "auth:1:0"},
        "source_ip": "192.0.2.5",
        "asset_id": "web01",
        "attributes": {},
        "origin": "observed",
    }
    r = client.post("/api/v1/agent/events", json={"events": [ev]}, headers=_hb(cred))
    assert r.status_code == 200 and r.json()["accepted"] == 1
    event_id = r.json()["results"][0]["event_id"]
    h = login(client)
    assert (
        client.get(f"/api/v1/events/{event_id}", headers=h).json()["producer_id"]
        == f"agent:{agent['agent_id']}"
    )
    assert (
        client.get(
            f"/api/v1/events/{event_id}", headers=login(client, "analyst@other.local")
        ).status_code
        == 404
    )

    hb = client.post("/api/v1/agent/heartbeat", json=_heartbeat_body(), headers=_hb(cred)).json()
    assert hb["agent_version_supported"] is True and hb["accepted_schema_versions"] == ["1.0"]
    old = client.post(
        "/api/v1/agent/heartbeat", json=_heartbeat_body(agent_version="0.0.9"), headers=_hb(cred)
    ).json()
    assert old["agent_version_supported"] is False  # version skew is reported, not silent
    listed = client.get("/api/v1/agents", headers=h).json()["items"][0]
    assert listed["health"] == "active" and listed["queue_depth"] == 3
    assert listed["sources"][0]["lag_seconds"] == 1.5
    assert (
        client.get("/api/v1/agents", headers=login(client, "analyst@other.local")).json()["total"]
        == 0
    )

    new = client.post("/api/v1/agent/rotate", headers=_hb(cred)).json()["credential"]
    assert (
        client.post(
            "/api/v1/agent/heartbeat", json=_heartbeat_body(), headers=_hb(cred)
        ).status_code
        == 401
    )
    assert (
        client.post("/api/v1/agent/heartbeat", json=_heartbeat_body(), headers=_hb(new)).status_code
        == 200
    )

    admin = login(client, "admin@demo.local")
    r = client.post(
        f"/api/v1/agents/{agent['agent_id']}/revoke",
        headers=admin,
        json={"reason": "decommissioned"},
    )
    assert r.status_code == 200 and r.json()["health"] == "revoked"
    for path, body in (
        ("/api/v1/agent/heartbeat", _heartbeat_body()),
        ("/api/v1/agent/events", {"events": [ev]}),
    ):
        assert client.post(path, json=body, headers=_hb(new)).status_code == 401
    # Another tenant's admin cannot revoke or see it.
    assert (
        client.post(
            f"/api/v1/agents/{agent['agent_id']}/revoke",
            headers=login(client, "analyst@other.local"),
            json={"reason": "x-tenant"},
        ).status_code
        == 403
    )


def test_heartbeat_rejects_unknown_fields_and_bad_status(client: Any) -> None:
    cred = _enroll(client, _token(client))["credential"]
    r = client.post(
        "/api/v1/agent/heartbeat", json=_heartbeat_body(command="reboot"), headers=_hb(cred)
    )
    assert r.status_code == 422
    bad = _heartbeat_body(sources=[{"name": "a", "type": "x", "status": "exploded"}])
    assert client.post("/api/v1/agent/heartbeat", json=bad, headers=_hb(cred)).status_code == 422


# ---- Real binary end to end -------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture()
def live_api(db_env: dict[str, str]) -> Any:
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "aegis.cli", "api", "--port", str(port)],
        cwd=BACKEND,
        env=db_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(base + "/api/v1/health", timeout=0.5).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.1)
    yield base
    proc.terminate()
    proc.wait(timeout=10)


@pytest.mark.skipif(shutil.which("go") is None, reason="Go toolchain not installed")
def test_real_agent_binary_end_to_end(live_api: str, client: Any, tmp_path: Path) -> None:
    binary = tmp_path / "aegis-agent"
    subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/aegis-agent"],
        cwd=AGENT_DIR,
        check=True,
        timeout=300,
    )
    log = tmp_path / "auth.log"
    shutil.copy(AGENT_DIR / "testdata/auth.log", log)
    cfg = tmp_path / "agent.json"
    cfg.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "config_version": 1,
                "server_url": live_api,
                "allow_insecure_localhost": True,
                "state_dir": str(tmp_path / "state"),
                "heartbeat_seconds": 5,
                "flush_seconds": 1,
                "sources": [
                    {
                        "name": "auth",
                        "type": "linux_auth",
                        "path": str(log),
                        "asset_id": "asset_web01",
                        "start_at_end": False,
                    }
                ],
            }
        )
    )
    token_file = tmp_path / "token"
    token_file.write_text(_token(client))
    enrolled = subprocess.run(
        [
            str(binary),
            "enroll",
            "-config",
            str(cfg),
            "-token-file",
            str(token_file),
            "-hostname",
            "web01",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert enrolled.returncode == 0, enrolled.stderr
    assert oct((tmp_path / "state/identity.json").stat().st_mode & 0o777) == "0o600"

    agent = subprocess.Popen(
        [str(binary), "run", "-config", str(cfg)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        h = login(client)
        deadline = time.time() + 30
        total = 0
        while time.time() < deadline:
            total = client.get("/api/v1/events?origin=observed", headers=h).json()["total"]
            if total >= 7:
                break
            time.sleep(0.3)
        assert total == 7
        drain()
        alerts = client.get("/api/v1/alerts", headers=h).json()["items"]
        assert len(alerts) == 1 and alerts[0]["group_key"]["source_ip"] == "192.0.2.42"
        assert alerts[0]["origin"] == "observed"
        assert client.get("/api/v1/incidents", headers=h).json()["total"] == 1

        deadline = time.time() + 15  # heartbeat interval is 5 s
        while time.time() < deadline:
            listed = client.get("/api/v1/agents", headers=h).json()["items"]
            if listed[0]["quarantined_lines"] == 1:  # the malformed fixture line
                break
            time.sleep(0.5)
        assert listed[0]["hostname"] == "web01" and listed[0]["last_seen_at"]
        assert listed[0]["quarantined_lines"] == 1 and listed[0]["queue_depth"] == 0

        admin = login(client, "admin@demo.local")
        client.post(
            f"/api/v1/agents/{listed[0]['agent_id']}/revoke",
            headers=admin,
            json={"reason": "end-to-end revocation test"},
        )
        with log.open("a") as fh:  # new data forces a delivery attempt with the revoked credential
            fh.write(
                "2026-01-01T09:20:00+00:00 web01 sshd[1]: Failed password for x from "
                "192.0.2.42 port 9 ssh2\n"
            )
        code = agent.wait(timeout=30)
        assert code == 3, agent.stderr.read() if agent.stderr else ""
    finally:
        if agent.poll() is None:
            agent.terminate()
            agent.wait(timeout=10)
    assert os.path.exists(tmp_path / "state/cursors.json")
