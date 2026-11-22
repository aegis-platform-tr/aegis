# ADR-0005: Response execution

Status: accepted; implemented in M5 for the simulation adapter

M1 performs **no** response actions. When response is added (M5) it will follow these rules:
actions are proposals with a typed, allow-listed action kind; execution requires a separate
human approval by a different principal holding `responses:approve`; every action has a scope,
a time limit, a dry-run, an automatic rollback path and a full audit trail; the default mode is
"recommend only"; no action may target systems outside an explicitly configured,
tenant-owned asset inventory. Autonomous execution without approval is out of scope.

**M5 implementation.** One typed action (`block_cidr`, /16 or narrower for IPv4, 5–1440 minutes)
on an explicitly managed resource. Lifecycle records: proposal (exact diff + SHA-256, base
policy revision, evidence, safeguards, 24 h expiry) → preview (before/after, conflicts,
protected-path overlap, affected addresses, rendered change, coverage) → approval by a
different principal holding `responses:approve` (30 min, bound to diff hash and policy
revision) → execute with a required `Idempotency-Key`, a row lock on the target, pre-snapshot,
apply, verification (rule present, protected paths reachable) and automatic restore when
verification fails → explicit rollback. Expired approvals, changed diffs/policies, protected
conflicts and unknown-impact adapters are refused and the refusal is persisted and audited.
`live_writes_enabled` is constrained to `false` in the schema: nftables and Windows Firewall
adapters render the exact change for review only. Live connectors remain unimplemented until
they can be exercised on authorized disposable infrastructure.
