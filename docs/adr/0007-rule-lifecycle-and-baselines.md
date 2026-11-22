# ADR-0007: Rule lifecycle, suppressions and baselines

Status: accepted (M3)

**Rules.** Built-in rules have `tenant_id NULL`, are readable by every tenant and writable by
none (RLS has no UPDATE path for them). Tenants create rules under their own namespace
(`<tenant>.<slug>`). Each revision is immutable and moves `draft → active → retired`; at most
one active revision per rule (partial unique index). Publishing an older revision is a
rollback and is audited as such. Built-ins are switched off per tenant through
`rule_tenant_settings`. Definitions are a discriminated union of bounded schemas
(`threshold`, `baseline`) with `extra=forbid`; group fields come from an allowlist plus
`attributes.<lowercase key>`. Draft revisions can be dry-run against fixtures or posted events
without persisting anything.

**Suppressions** are tenant-scoped, entity-scoped (optionally rule-scoped), require a reason
and an expiry (≤ 30 days) and are revocable. A suppressed alert is still stored with its
evidence and an explanation naming the suppression; it is not correlated into an incident.

**Baselines** aggregate per-service event-time minutes in PostgreSQL and classify closed
minutes with median/MAD plus source novelty and error rate. Anomalous minutes are excluded
from later baselines. See `docs/evaluation/ddos-baseline.md`.
