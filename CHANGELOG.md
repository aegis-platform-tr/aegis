# Changelog

## 0.2.0-rc1 — 2026-11-22 (M2–M6)
- M2: agent enrollment/rotation/revocation/heartbeats; Go agent with linux-auth, Suricata,
  Zeek and Windows Security parsers, bounded spool, quarantine, retry.
- M3: tenant rule lifecycle with dry-run and rollback, suppressions, IDS/Windows rules,
  service baselines (DDoS signal), multi-source correlation, notes and assignment.
- M4: AI Security Gateway with mock provider, tool broker, redacted audit and evaluation set.
- M5: response proposals, preview, independent approval, idempotent execution, verification,
  rollback (simulation adapter; live writes disabled).
- M6: overview/system status, dashboard for all modules, upgrade and outage tests,
  benchmark, SBOMs, secret scan, release notes and handoff.

## 0.1.0 — 2026-11-22 (M1 vertical slice)
- Event contract v1, authenticated idempotent ingestion, credential redaction.
- Threshold rule `auth.bruteforce.source_asset`, alert fingerprints, entity/time correlation.
- Incidents with state machine, history, optimistic concurrency.
- Tenant isolation with row-level security; append-only audit log.
- React dashboard; synthetic fixture pack; Docker Compose and CI definitions.
