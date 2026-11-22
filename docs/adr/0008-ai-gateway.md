# ADR-0008: AI Security Gateway

Status: accepted (M4)

**Decision.** Every model interaction goes through `aegis/ai/gateway.py`: request type and
budget checks → provider policy → input inspection (secrets redacted, injection *signals*
recorded, all telemetry/documents wrapped as UNTRUSTED data) → principal pseudonymization
(tenant policy `share_principals=false` by default) → provider call → typed tool broker →
buffered output inspection (secrets, shell commands, evidence references validated against
the tenant-scoped input set and tool results) → audit record without the raw prompt (SHA-256
and length only). Decisions use the fixed vocabulary `allow, flag, redact, deny,
require_review, dependency_unavailable`.

Safety does not depend on detection quality. Write tools need: the `responses:propose`
capability, tenant policy `allow_write_proposals`, the `draft_response` request type, and a
context without injection signals; even then they only create a proposal that needs preview
and an independent approver (ADR-0005). Read tools are tenant-checked.

Only a deterministic offline **mock** provider is implemented. `cloud_disabled` raises before
any I/O, so selecting it can never transmit content. No ML classifier is used: there is no
labeled data to train or evaluate one honestly (Section 23.3); the evaluation set
(`docs/evaluation/ai-gateway.md`) reports false positives and negatives of the deterministic
checks. AI output is labeled generated/unverified, carries provider/model/policy revision and
is optional: ingestion, detection and incident handling never depend on it.

**Failure modes.** Provider timeout/outage: `summarize_incident` returns a disclosed
deterministic fallback; `ask` returns no answer. Budget exhausted or provider `none`: `deny`
without a provider call. Streaming is not offered (output is buffered so inspection happens
before release).
