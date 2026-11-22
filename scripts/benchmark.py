#!/usr/bin/env python3
"""Ingestion and processing benchmark against a running local AEGIS (Section 26).

Sends synthetic events at a fixed rate through the authenticated API, then reads
server-side timestamps to compute processing lag and event-to-alert latency.
No network traffic is generated other than HTTP to the local API.

usage: python scripts/benchmark.py --rate 100 --seconds 180 --api http://127.0.0.1:8000 \
         --user analyst@other.local --db-url postgresql://admin:pw@127.0.0.1/aegis --pids API,WORKER
"""

from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import threading
import time
import uuid
from datetime import UTC, datetime

import httpx
import psycopg

BATCH = 20


def pct(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    values = sorted(values)
    k = max(0, min(len(values) - 1, round(p / 100 * (len(values) - 1))))
    return values[k]


def event(i: int, run: str, now: datetime, burst_ip: str | None) -> dict:
    base = {"schema_version": "1.0", "observed_at": now.isoformat(), "occurred_at": now.isoformat(),
            "source": {"adapter": "benchmark", "adapter_version": "1", "native_id": f"{run}-{i}"},
            "origin": "synthetic", "attributes": {"bench_run": run}}
    if burst_ip:
        return base | {"event_category": "authentication", "event_type": "login_failure",
                       "source_ip": burst_ip, "asset_id": "bench-asset", "principal": "root"}
    if i % 2:
        return base | {"event_category": "network", "event_type": "http_request",
                       "source_ip": f"198.51.100.{random.randint(101, 140)}",
                       "destination_ip": "198.51.100.20", "destination_port": 8443,
                       "attributes": {"bench_run": run, "status": 200}}
    return base | {"event_category": "authentication", "event_type": "login_success",
                   "source_ip": f"198.51.100.{random.randint(1, 99)}", "asset_id": "bench-asset"}


def proc_sample(pid: int) -> tuple[float, int]:
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().split(")")[1].split()
    cpu = (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    rss = 0
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                rss = int(line.split()[1])
    return cpu, rss


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rate", type=int, default=100)
    ap.add_argument("--seconds", type=int, default=180)
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--user", default="analyst@other.local")
    ap.add_argument("--db-url", required=True)
    ap.add_argument("--pids", default="")
    args = ap.parse_args()
    pw = os.environ["AEGIS_DEV_PASSWORD"]
    run = uuid.uuid4().hex[:8]
    client = httpx.Client(base_url=args.api, timeout=30)
    token = client.post("/api/v1/auth/login", json={"username": args.user, "password": pw}).json()[
        "access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    pids = [int(p) for p in args.pids.split(",") if p]
    cpu0 = {p: proc_sample(p)[0] for p in pids}
    max_rss = dict.fromkeys(pids, 0)
    acks: list[float] = []
    errors = 0
    sent = 0
    burst_every = 10 * args.rate  # one brute-force burst (6 failures) per ~10 s
    interval = BATCH / args.rate
    start = time.monotonic()
    nxt = start
    i = 0
    lock = threading.Lock()
    while time.monotonic() - start < args.seconds:
        now = datetime.now(UTC)
        batch = []
        for _ in range(BATCH):
            burst_ip = None
            if i % burst_every < 6:
                burst_ip = f"192.0.2.{(i // burst_every) % 250 + 1}"
            batch.append(event(i, run, now, burst_ip))
            i += 1
        t0 = time.monotonic()
        try:
            r = client.post("/api/v1/events", json={"events": batch}, headers=headers)
            ok = r.status_code == 200
        except httpx.HTTPError:
            ok = False
        with lock:
            acks.append((time.monotonic() - t0) * 1000)
            if ok:
                sent += len(batch)
            else:
                errors += 1
        for p in pids:
            max_rss[p] = max(max_rss[p], proc_sample(p)[1])
        nxt += interval
        delay = nxt - time.monotonic()
        if delay > 0:
            time.sleep(delay)
    elapsed = time.monotonic() - start
    # wait for the worker to drain this run
    deadline = time.time() + 600
    with psycopg.connect(args.db_url) as db:
        while time.time() < deadline:
            pending = db.execute(
                "SELECT count(*) FROM work_items w JOIN security_events e ON e.id = w.ref_id "
                "WHERE w.status = 'pending' AND e.attributes->>'bench_run' = %s", (run,)
            ).fetchone()[0]
            if pending == 0:
                break
            time.sleep(1)
        drained_at = time.monotonic()
        lag = [float(r[0]) * 1000 for r in db.execute(
            "SELECT extract(epoch FROM w.updated_at - e.ingested_at) FROM work_items w "
            "JOIN security_events e ON e.id = w.ref_id WHERE e.attributes->>'bench_run' = %s "
            "AND w.status = 'done'", (run,)).fetchall()]
        dead = db.execute(
            "SELECT count(*) FROM work_items w JOIN security_events e ON e.id = w.ref_id "
            "WHERE w.status = 'dead' AND e.attributes->>'bench_run' = %s", (run,)).fetchone()[0]
        retried = db.execute(
            "SELECT count(*) FROM work_items w JOIN security_events e ON e.id = w.ref_id "
            "WHERE w.attempts > 1 AND e.attributes->>'bench_run' = %s", (run,)).fetchone()[0]
        # Event-to-alert: alert creation time minus ingestion time of the event that crossed
        # the threshold (5th by ingestion order), for alerts first created during this run.
        e2a = [float(r[0]) * 1000 for r in db.execute(
            "SELECT extract(epoch FROM a.evaluated_at - (array_agg(e.ingested_at ORDER BY "
            "e.ingested_at))[5]) FROM detection_alerts a JOIN alert_events ae ON ae.alert_id = a.id "
            "JOIN security_events e ON e.id = ae.event_id WHERE a.rule_id = "
            "'auth.bruteforce.source_asset' GROUP BY a.id, a.evaluated_at HAVING "
            "bool_and(e.attributes->>'bench_run' = %s)", (run,)).fetchall()
            if r[0] is not None]
    cpu = {p: round(proc_sample(p)[0] - cpu0[p], 1) for p in pids}
    result = {
        "run": run, "target_rate_eps": args.rate, "duration_s": round(elapsed, 1),
        "events_acknowledged": sent, "achieved_rate_eps": round(sent / elapsed, 1),
        "request_errors": errors, "batch_size": BATCH,
        "ack_ms": {"p50": round(pct(acks, 50), 1), "p95": round(pct(acks, 95), 1),
                   "p99": round(pct(acks, 99), 1), "n": len(acks)},
        "processing_lag_ms": {"p50": round(pct(lag, 50), 1), "p95": round(pct(lag, 95), 1),
                              "p99": round(pct(lag, 99), 1), "n": len(lag)},
        "event_to_alert_ms": {"p50": round(pct(e2a, 50), 1), "p95": round(pct(e2a, 95), 1),
                              "max": round(max(e2a), 1) if e2a else None, "n": len(e2a)},
        "drain_after_send_s": round(drained_at - (start + elapsed), 1),
        "dead_letters": dead, "retried": retried,
        "cpu_seconds": cpu, "max_rss_kib": max_rss,
        "mean_ack_ms": round(statistics.mean(acks), 1) if acks else None,
    }
    print(json.dumps(result, indent=2, default=float))


if __name__ == "__main__":
    main()
