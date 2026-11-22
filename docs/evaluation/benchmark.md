# Benchmark: ingestion and processing (2026-11-22)

Reference environment: Linux build workspace, **2 vCPU, 8 GiB RAM**, PostgreSQL 16.15 on the
same host (default settings), Python 3.13, one API process (uvicorn, single worker), one
AEGIS worker process, one tenant, one benchmark client on the same host. Not a laptop and
not a production sizing statement.

Command: `python scripts/benchmark.py --rate 100 --seconds 180 --db-url … --pids API,WORKER`
(synthetic events, batch size 20, 50 % `http_request` for one service feeding the baseline,
~50 % `login_success`, plus one 6-event brute-force burst every 10 s). Run id `ef0488db`.

| Metric | Provisional target (Section 26) | Measured |
|---|---|---|
| Sustained ingest rate | 100 events/s | **100.0 events/s** for 180 s (18,000 events acknowledged) |
| Request errors / rejections | — | 0 / 0 |
| Durable ingest acknowledgement (per 20-event batch) | p95 ≤ 500 ms | p50 59.6 ms · **p95 77.9 ms** · p99 90.2 ms (n = 900) |
| Processing lag (ingested → worker done) | — | p50 632 ms · p95 1,098 ms · p99 1,162 ms (n = 18,000) |
| Event-to-alert (threshold-crossing event ingested → alert created) | p95 ≤ 5 s | p50 417 ms · max 831 ms (**n = 6**, see note) |
| Backlog after sending stopped | — | drained within 1.0 s |
| Dead letters / retries | — | 0 / 0 |
| CPU used over the run | — | API 37.8 s (≈21 % of one core) · worker 87.6 s (≈49 %) |
| Peak RSS | — | API 109 MiB · worker 75 MiB |

Notes and deviations:
- Duration was **3 minutes, not the 15 minutes** in the provisional target, to fit the build
  session. The worker kept pace (lag stayed ~1 s), but long-run behavior (table growth,
  autovacuum, index bloat) is unmeasured.
- Event-to-alert has only 6 clean samples: 12 of the 18 bursts reused source addresses from
  an aborted earlier run inside the same 5-minute window and merged into older alerts, so
  they were excluded (the script now filters to alerts whose evidence is entirely from the
  run). Treat the figure as indicative.
- Worker throughput ceiling was not measured here; the separate DDoS fixture run processed
  ~125 events/s with baseline updates on every event (`docs/evaluation/ddos-baseline.md`).
