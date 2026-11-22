# Selected controls mapped to code and evidence

Reference: OWASP ASVS (https://asvs.owasp.org/). This is a selective mapping of the controls
AEGIS implements, not a claim of ASVS level compliance; the version and scope were not
formally assessed.

| Area | Control as implemented | Code | Evidence | Gap |
|---|---|---|---|---|
| Authentication | Argon2id password hashes; uniform failure response; equalized timing for unknown users | `aegis/security.py` | `test_repeated_login_failures_are_throttled_and_audited` | No MFA/SSO |
| Authentication | Throttle 5 failures / 5 min / username; all attempts audited | `api/routes_auth.py` | same | In-process only (single replica) |
| Session | Short-lived JWT (15 min), `iss/aud/exp/nbf/jti` required, HS256 only, revocation on logout, token kept in memory in the UI | `security.py`, `api/deps.py`, `apps/dashboard/src/api.ts` | `test_requests_without_valid_token_are_rejected`, `test_logout_revokes_token` | No refresh token; manual key rotation |
| Access control | Capability per route; deny by default; tenant from credential only; 404 on cross-tenant | `security.py`, all routers | `test_capabilities_are_enforced_server_side`, tenant isolation tests | — |
| Access control | PostgreSQL RLS (FORCE) with a non-owner runtime role; built-in rules immutable | migrations 0001–0005 | `test_rls_blocks_runtime_role_*`, `test_audit_log_and_events_are_append_only_*` | Login/agent-credential tables are not RLS-scoped (by design, documented) |
| Validation | Strict schemas (`extra=forbid`), bounded sizes, timezone-aware timestamps, IP parsing, allowlisted rule operators | `contracts.py`, `detection.py`, routers | `test_malformed_oversized_and_partial_batches`, `test_rule_validation_and_permissions` | — |
| Output encoding | React text rendering only; CSP and security headers; no SQL/traceback in errors | dashboard, `api/app.py`, `api/errors.py` | `test_error_responses_are_structured_and_safe`, `test_database_outage_*` | CSP via nginx only in container path |
| Data protection | Credential-key redaction at ingest; SQL parameters hidden from logs; prompts not stored (hash + length) | `redaction.py`, `db.py`, `ai/gateway.py` | `test_credentials_are_redacted_and_not_logged`, `test_ai_audit_records_are_redacted_*` | Free-text secrets not detected |
| Logging | Structured JSON logs with allowlisted fields; append-only audit table | `logging_setup.py`, `audit.py` | audit assertions across tests | No log shipping / tamper evidence |
| Business logic | Idempotent ingest and execute; optimistic locking; separation of duties; approval bound to diff hash and policy revision | `ingestion.py`, `responses.py` | M1/M5 tests incl. concurrency | — |
| Files/config | Agent config strict, no command fields; credential file 0600; tokens never on the command line | `agent/internal/config`, `state` | Go tests, `test_real_agent_binary_end_to_end` | — |
| AI (OWASP GenAI LLM06 Excessive Agency) | Typed tool broker, read/write separation, write → proposal only, human approval | `ai/tools.py`, `responses.py` | `docs/evaluation/ai-gateway.md` | Pattern-based injection signals are bypassable (documented) |

NIST SP 800-61 Rev. 3 alignment is limited to incident lifecycle record-keeping (states,
actor/time/reason history, notes, containment verification, closure reasons); no formal
mapping was performed.
