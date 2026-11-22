# ADR-0002: Tenant isolation enforcement

Status: accepted (M1)

**Decision.** Two independent layers:
1. *Application*: tenant comes only from the validated token (`tid` claim). Every repository
   query filters by it. Cross-tenant reads return `404`, never `403`, to avoid disclosing
   existence. List totals and filters are computed in the same scope.
2. *Database*: row-level security with `FORCE` on all tenant data tables. Policies compare
   `tenant_id` to the transaction-local setting `aegis.tenant_id`
   (`set_config(..., true)`), which resets at commit, so pooled connections cannot leak
   scope. The runtime role `aegis_app` owns nothing and lacks `BYPASSRLS`; migrations run as
   `aegis_owner`.

`tenants`, `users` and `revoked_tokens` are not RLS-protected (login must resolve a user before
a tenant is known); they are accessed only by dedicated code paths. `audit_logs` allows inserts
with `tenant_id NULL` (pre-authentication events) but such rows are not readable by tenants.

**Consequences.** A missing `WHERE tenant_id` in new code fails closed (zero rows) instead of
leaking. Inserts into `audit_logs` must not use `RETURNING` (PostgreSQL applies SELECT policies
to it). Tests assert both layers.
