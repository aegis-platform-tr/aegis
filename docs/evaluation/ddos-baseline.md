# Evaluation: service baseline / DDoS signal (rule `ddos.service_baseline` r1)

Date: 2026-11-22 · Environment: Linux build workspace, PostgreSQL 16, single worker ·
Data: `sample_data/fixtures/ddos-baseline-demo.json` (generator seed 20260102, 2,879 synthetic
HTTP events, one service, RFC 5737 / RFC 2544 addresses). Reproduce:
`python sample_data/generators/ddos_baseline_demo.py`, import the pack, run the worker, read
`GET /api/v1/network/services/198.51.100.10:443/minutes`. Asserted by
`backend/tests/test_m3_detection.py::test_ddos_baseline_separates_legitimate_spike_from_anomaly`.

| Labeled segment (event-time minutes) | Minutes | Classification | Alerts |
|---|---:|---|---:|
| Warm-up (0–14) | 15 | warming_up | 0 |
| Baseline traffic | 35 | normal | 0 |
| Legitimate deployment spike, ~8× volume from known clients (40–42) | 3 | expected_burst | **0** |
| Surge from ~300 new sources, ~35 % HTTP 503 (50–52) | 3 | anomaly | **1** (one alert spanning all 3 minutes) |

- False positives on the labeled burst: **0 of 3 burst minutes** (0 of 53 non-attack minutes).
- Detection on the labeled attack: **3 of 3 attack minutes** flagged, merged into one alert and
  one incident (`service:198.51.100.10:443`).
- Labeling method: by construction (generator segments). Sample size is tiny and synthetic;
  these numbers demonstrate the mechanism, not field accuracy.
- Throughput of this run: import 2,879 events in 6.3 s; worker processed them in 23.1 s
  (~125 events/s including per-event rule evaluation and baseline updates).

## Known limitations
- One vantage point; no corroboration from a second sensor yet, so confidence is fixed at 0.5.
- No seasonality (daily/weekly) model: a regular daily peak larger than the 30-minute history
  would be classified by the source mix only.
- A legitimate surge of *new* clients (marketing launch, CDN failover, shared proxy change
  with many new egress IPs) would look like the anomaly when errors are also high. Untested.
- Minutes with no records are `missing_telemetry`; zero traffic and sensor loss are not
  distinguishable without sensor heartbeats.
- Events arriving after a minute was evaluated (grace = 1 minute) update aggregates and
  `late_events`, but the classification is not recomputed.
