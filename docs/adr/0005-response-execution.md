# ADR-0005: Response execution (not implemented in M1)

Status: accepted as a constraint

M1 performs **no** response actions. When response is added (M5) it will follow these rules:
actions are proposals with a typed, allow-listed action kind; execution requires a separate
human approval by a different principal holding `responses:approve`; every action has a scope,
a time limit, a dry-run, an automatic rollback path and a full audit trail; the default mode is
"recommend only"; no action may target systems outside an explicitly configured,
tenant-owned asset inventory. Autonomous execution without approval is out of scope.
