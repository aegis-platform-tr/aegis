"""Generate sample_data/fixtures/ddos-baseline-demo.json deterministically (seeded).

Service 198.51.100.10:443 (RFC 5737). Timeline (event-time minutes from 2026-01-02T10:00Z):
  0-39   baseline: ~20 req/min from 10 known clients (198.51.100.101-110), few 404s
  40-42  LEGITIMATE spike (deployment rollout / cache warm-up): ~160 req/min from the same
         10 known clients, ~1% 5xx
  43-49  baseline
  50-52  ANOMALOUS pattern: ~450 req/min from ~300 never-seen sources in 198.18.0.0/15
         (RFC 2544 benchmarking range) with ~35% HTTP 503
  53-57  baseline (so minutes up to 55 are closed and evaluated)
Expected: exactly one alert covering minutes 50-52; minutes 40-42 classified expected_burst.
"""

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

SEED = 20260102
START = datetime(2026, 1, 2, 10, 0, tzinfo=UTC)
KNOWN = [f"198.51.100.{i}" for i in range(101, 111)]
SERVICE_IP, SERVICE_PORT = "198.51.100.10", 443


def main() -> None:
    rng = random.Random(SEED)
    events = []
    n = 0

    def emit(minute: int, src: str, status: int) -> None:
        nonlocal n
        n += 1
        ts = START + timedelta(minutes=minute, seconds=rng.uniform(0, 59.9))
        events.append({
            "schema_version": "1.0", "event_category": "network", "event_type": "http_request",
            "occurred_at": ts.isoformat().replace("+00:00", "Z"),
            "observed_at": (ts + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
            "source": {"adapter": "fixture", "adapter_version": "1", "native_id": f"ddos-{n:05d}"},
            "asset_id": "asset_demo_lb01", "source_ip": src, "destination_ip": SERVICE_IP,
            "destination_port": SERVICE_PORT, "protocol": "tcp",
            "attributes": {"host": "shop.example", "method": "GET", "path": "/", "status": status},
            "origin": "synthetic",
        })

    def baseline(minute: int) -> None:
        for _ in range(rng.randint(18, 22)):
            emit(minute, rng.choice(KNOWN), 404 if rng.random() < 0.03 else 200)

    for m in range(0, 40):
        baseline(m)
    for m in range(40, 43):
        for _ in range(rng.randint(150, 170)):
            emit(m, rng.choice(KNOWN), 502 if rng.random() < 0.01 else rng.choice([200, 304]))
    for m in range(43, 50):
        baseline(m)
    attackers = [f"198.18.{rng.randint(0, 255)}.{rng.randint(1, 254)}" for _ in range(300)]
    for m in range(50, 53):
        for _ in range(rng.randint(440, 460)):
            emit(m, rng.choice(attackers), 503 if rng.random() < 0.35 else 200)
    for m in range(53, 58):
        baseline(m)

    events.sort(key=lambda e: e["occurred_at"])
    pack = {
        "fixture_pack": "ddos-baseline-demo", "version": "1", "origin": "synthetic",
        "description": "Synthetic per-minute HTTP telemetry for one service: a legitimate "
                       "deployment spike from known clients and a later surge from ~300 new "
                       "sources with 503s. Non-routable documentation/benchmark addresses only.",
        "generator": {"script": "sample_data/generators/ddos_baseline_demo.py", "seed": SEED},
        "expected": {"alerts": [{"rule_id": "ddos.service_baseline",
                                 "service_key": f"{SERVICE_IP}:{SERVICE_PORT}",
                                 "minutes": ["2026-01-02T10:50Z", "2026-01-02T10:52Z"]}],
                     "expected_burst_minutes": ["2026-01-02T10:40Z", "2026-01-02T10:42Z"]},
        "events": events,
    }
    out = Path(__file__).resolve().parents[1] / "fixtures/ddos-baseline-demo.json"
    out.write_text(json.dumps(pack, separators=(",", ":")) + "\n")
    print(f"wrote {len(events)} events to {out}")


if __name__ == "__main__":
    main()
