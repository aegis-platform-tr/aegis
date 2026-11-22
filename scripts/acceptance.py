#!/usr/bin/env python3
"""Local demonstration acceptance flow (directive Section 20.3), run against a live stack.

usage: AEGIS_DEV_PASSWORD=... python scripts/acceptance.py --api http://127.0.0.1:8000 \
          [--restart-worker-cmd "systemctl restart aegis-worker"]

Expects a freshly migrated and seeded local-demo database. Prints PASS/FAIL per check and
exits non-zero on any failure. Makes no changes outside the AEGIS API (simulation adapter only).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from typing import Any

import httpx

RESULTS: list[tuple[str, bool, str]] = []


def check(step: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((step, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {step}{' — ' + detail if detail else ''}", flush=True)


class Api:
    def __init__(self, base: str, password: str) -> None:
        self.c = httpx.Client(base_url=base, timeout=120)
        self.pw = password
        self._tokens: dict[str, str] = {}

    def h(self, user: str) -> dict[str, str]:
        if user not in self._tokens:
            r = self.c.post("/api/v1/auth/login", json={"username": user, "password": self.pw})
            r.raise_for_status()
            self._tokens[user] = r.json()["access_token"]
        return {"Authorization": f"Bearer {self._tokens[user]}"}

    def get(self, path: str, user: str = "analyst@demo.local") -> Any:
        return self.c.get(path, headers=self.h(user))

    def post(self, path: str, user: str = "analyst@demo.local", **kw: Any) -> Any:
        headers = self.h(user) | kw.pop("headers", {})
        return self.c.post(path, headers=headers, **kw)

    def drain(self, timeout: float = 300) -> dict[str, Any]:
        deadline = time.time() + timeout
        q: dict[str, Any] = {}
        while time.time() < deadline:
            q = self.get("/api/v1/system/status").json()["queue"]
            if q["pending"] == 0:
                return q
            time.sleep(1)
        return q


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--restart-worker-cmd", default="")
    args = ap.parse_args()
    api = Api(args.api, os.environ["AEGIS_DEV_PASSWORD"])

    # 1. Startup: readiness waits for dependencies; migrations at head.
    r = api.c.get("/api/v1/ready")
    check("1 readiness", r.status_code == 200 and r.json()["checks"] == {
        "database": "ok", "migrations": "ok"}, r.text[:120])

    # 2. Authenticate as a dev analyst and import fixtures through the normal path.
    imported = {}
    for pack in ("auth-bruteforce-demo", "ids-correlation-demo", "ddos-baseline-demo"):
        res = api.post(f"/api/v1/fixtures/{pack}/import").json()
        imported[pack] = res
    check("2 fixture import", all(v["rejected"] == 0 for v in imported.values()),
          ", ".join(f"{k}: {v['accepted']} new/{v['duplicate']} dup" for k, v in imported.items()))
    q = api.drain()
    events = api.get("/api/v1/events?limit=200").json()
    check("2 synthetic label on every event",
          bool(events["items"]) and all(e["origin"] == "synthetic" for e in events["items"]),
          f"{events['total']} events")

    # 3. Follow IDs: receipt -> event -> alert -> incident -> timeline; distinct times.
    incidents = api.get("/api/v1/incidents").json()["items"]
    brute = next((i for i in incidents if i["correlation_key"] == "source_ip:192.0.2.42"), None)
    ok3 = False
    if brute:
        d = api.get(f"/api/v1/incidents/{brute['incident_id']}").json()
        ev = next(t for t in d["timeline"] if t["kind"] == "event")
        alert = d["alerts"][0]
        detail = api.get(f"/api/v1/events/{ev['ref_id']}").json()
        ok3 = (ev["times"]["occurred_at"] != ev["times"]["ingested_at"]
               and alert["evaluated_at"] and detail["event_id"] == ev["ref_id"]
               and len(d["alerts"]) == 2)
    check("3 evidence chain + source/receipt/evaluation times", ok3,
          f"{len(incidents)} incidents")

    # 4. Re-import and restart the worker: logical counts stay stable.
    before = api.get("/api/v1/overview").json()
    again = api.post("/api/v1/fixtures/auth-bruteforce-demo/import").json()
    if args.restart_worker_cmd:
        subprocess.run(args.restart_worker_cmd, shell=True, check=False)  # noqa: S602
    q = api.drain()
    after = api.get("/api/v1/overview").json()
    stable = (before["events_total"] == after["events_total"]
              and before["alerts_by_severity"] == after["alerts_by_severity"]
              and before["incidents_by_status"] == after["incidents_by_status"])
    check("4 replay + worker restart keep counts stable", stable and again["accepted"] == 0,
          f"duplicates {again['duplicate']}, queue {q}")

    # 5. Another tenant sees nothing (detail, list, counts, network, AI, responses).
    o = "analyst@other.local"
    leaks = [
        api.get(f"/api/v1/incidents/{brute['incident_id']}", o).status_code != 404 if brute else True,
        api.get("/api/v1/incidents", o).json()["total"] != 0,
        api.get("/api/v1/events?event_type=login_failure", o).json()["total"] != 0,
        api.get("/api/v1/overview", o).json()["events_total"] != 0,
        api.get("/api/v1/network/services", o).json() != [],
        api.post("/api/v1/ai/requests", o, json={"capability": "summarize_incident",
                                                 "incident_id": brute["incident_id"]}
                 ).status_code != 404 if brute else True,
    ]
    check("5 tenant isolation", not any(leaks), f"leak flags {leaks}")

    # 6. Benign AI request, deterministic refusal, redacted audit, pipeline independent of AI.
    admin = "admin@demo.local"
    base_policy = {"provider": "mock", "allow_tools": True, "allow_write_proposals": False,
                   "share_principals": False, "max_requests_per_day": 500}
    benign = api.post("/api/v1/ai/requests", json={"capability": "ask",
                                                   "prompt": "What does this rule detect?"}).json()
    api.c.put("/api/v1/ai/policy", headers=api.h(admin),
              json=base_policy | {"provider": "none", "reason": "acceptance: refusal check"})
    refused = api.post("/api/v1/ai/requests", json={"capability": "ask", "prompt": "hello"}).json()
    api.c.put("/api/v1/ai/policy", headers=api.h(admin),
              json=base_policy | {"reason": "acceptance: restore"})
    outage = api.post("/api/v1/ai/requests", json={"capability": "ask",
                                                   "prompt": "x [[mock:outage]]"}).json()
    audit = api.get("/api/v1/ai/requests", admin).json()
    check("6 AI benign/refusal/outage + redacted audit",
          benign["decision"] == "allow" and refused["decision"] == "deny"
          and not refused["provider_called"] and outage["decision"] == "dependency_unavailable"
          and all("prompt" not in r for r in audit) and api.c.get("/api/v1/ready").status_code == 200,
          f"{benign['decision']}/{refused['decision']}/{outage['decision']}")

    # 7. Simulated defensive rule: preview scope + diff, audit, host untouched.
    pr = api.post("/api/v1/responses", "proposer@demo.local", json={
        "resource_id": "res_sim_tenant_demo", "cidr": "203.0.113.0/24", "minutes": 30,
        "reason": "acceptance: fictional defensive rule"}).json()
    pv = api.post(f"/api/v1/responses/{pr['proposal_id']}/preview", "proposer@demo.local").json()
    prev = pv.get("preview") or {}
    api.post(f"/api/v1/responses/{pr['proposal_id']}/approve", "approver@demo.local",
             json={"reason": "acceptance approval"})
    ex = api.post(f"/api/v1/responses/{pr['proposal_id']}/execute", "approver@demo.local",
                  headers={"Idempotency-Key": f"acceptance-{pr['proposal_id']}"}).json()
    acts = [a["action"] for a in api.get("/api/v1/audit?limit=50", admin).json()["items"]]
    check("7 simulation preview/approve/execute audited, host untouched",
          prev.get("coverage") == "known" and prev.get("host_state", "").startswith("unchanged")
          and ex.get("status") == "verified"
          and {"response.propose", "response.preview", "response.approve",
               "response.execute"} <= set(acts), f"status {ex.get('status')}")

    # 8. Empty / disabled / degraded states are explicit, never zero-filled.
    empty = api.get("/api/v1/overview", o).json()
    status = api.get("/api/v1/system/status").json()
    comp = {c["name"]: c["status"] for c in status["components"]}
    check("8 empty/disabled states explicit",
          empty["last_event_ingested_at"] is None
          and empty["network"]["status"] == "no network telemetry yet"
          and comp.get("live_firewall_adapters") == "disabled", str(comp))

    failed = [s for s, ok, _ in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
