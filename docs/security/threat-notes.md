# Threat notes (M1)

| Threat | Control in M1 | Test |
|---|---|---|
| Cross-tenant read via ID guessing or filters | tenant from token; query filter; RLS; 404 | `test_other_tenant_cannot_read_detail_list_or_counts`, `test_rls_blocks_runtime_role_*` |
| Tenant spoofing in payload | `tenant_id` field rejected | `test_tenant_claim_in_payload_is_rejected` |
| Forged / expired / `alg=none` tokens | signature, `aud`, `iss`, `exp` checks; HS256 only | `test_requests_without_valid_token_are_rejected` |
| Credential stuffing | throttle (5 / 5 min / username), audit, uniform errors | `test_repeated_login_failures_are_throttled_and_audited` |
| Privilege escalation via UI | server-side capability checks | `test_capabilities_are_enforced_server_side` |
| Resource exhaustion via ingest | body/batch/attribute limits, no compressed bodies, statement timeout | `test_malformed_oversized_and_partial_batches` |
| Secrets in telemetry | key-based redaction; values not echoed in errors; SQL params hidden | `test_credentials_are_redacted_and_not_logged` |
| Evidence tampering by the app | no UPDATE/DELETE grants on events, links, audit | `test_audit_log_and_events_are_append_only_for_runtime_role` |
| Duplicate alerts/incidents under concurrency | unique fingerprints, advisory locks, single-tx processing | `test_parallel_*` |
| XSS through event content | React text rendering only; CSP in nginx | manual review; no `dangerouslySetInnerHTML` |
| Path traversal in fixture import | name allow-list regex, fixed directory, synthetic-only | `test_fixture_import_endpoint_*` |

Residual risks: in-process throttle; JWT secret rotation is manual; no MFA; audit rows are
append-only for the app role but not cryptographically chained; Docker stack hardening is
unverified.
