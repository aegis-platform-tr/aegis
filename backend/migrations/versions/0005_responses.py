"""M5: managed defensive resources, response proposals, approvals and executions.

Revision ID: 0005_responses
Revises: 0004_ai_gateway
"""

from __future__ import annotations

import os

from alembic import op

revision = "0005_responses"
down_revision = "0004_ai_gateway"
branch_labels = None
depends_on = None

DDL = """
CREATE TABLE managed_resources (
    id                   varchar(40) PRIMARY KEY,
    tenant_id            varchar(64) NOT NULL REFERENCES tenants(id),
    name                 varchar(120) NOT NULL,
    adapter              varchar(32) NOT NULL
                         CHECK (adapter IN ('simulation', 'nftables', 'windows_firewall')),
    interface            varchar(64) NOT NULL,
    protected_cidrs      jsonb NOT NULL DEFAULT '[]'::jsonb,
    enabled              boolean NOT NULL DEFAULT true,
    live_writes_enabled  boolean NOT NULL DEFAULT false CHECK (live_writes_enabled = false),
    policy_revision      integer NOT NULL DEFAULT 1,
    policy_snapshot      jsonb NOT NULL DEFAULT '{"rules": []}'::jsonb,
    test_fail_mode       varchar(24) CHECK (test_fail_mode IN ('apply_error','verify_error','unknown_result')),
    created_by           varchar(200) NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE response_proposals (
    id                    varchar(40) PRIMARY KEY,
    tenant_id             varchar(64) NOT NULL REFERENCES tenants(id),
    resource_id           varchar(40) NOT NULL REFERENCES managed_resources(id),
    action_type           varchar(32) NOT NULL CHECK (action_type IN ('block_cidr')),
    payload               jsonb NOT NULL,
    diff                  jsonb NOT NULL,
    diff_sha256           char(64) NOT NULL,
    base_policy_revision  integer NOT NULL,
    author                varchar(200) NOT NULL,
    author_kind           varchar(8) NOT NULL CHECK (author_kind IN ('human','ai')),
    reason                text NOT NULL,
    evidence              jsonb NOT NULL DEFAULT '{}'::jsonb,
    safeguards            jsonb NOT NULL,
    status                varchar(20) NOT NULL CHECK (status IN
                          ('proposed','previewed','approval_pending','approved','denied',
                           'expired','invalidated','applying','applied','verified','failed',
                           'partial','rolled_back')),
    status_reason         text,
    preview               jsonb,
    expires_at            timestamptz NOT NULL,
    version               integer NOT NULL DEFAULT 1,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_proposals_tenant ON response_proposals (tenant_id, created_at DESC);

CREATE TABLE response_approvals (
    id                    varchar(40) PRIMARY KEY,
    tenant_id             varchar(64) NOT NULL REFERENCES tenants(id),
    proposal_id           varchar(40) NOT NULL REFERENCES response_proposals(id),
    approver              varchar(200) NOT NULL,
    decision              varchar(8) NOT NULL CHECK (decision IN ('approved','denied')),
    diff_sha256           char(64) NOT NULL,
    base_policy_revision  integer NOT NULL,
    reason                text NOT NULL,
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE response_executions (
    id                varchar(40) PRIMARY KEY,
    tenant_id         varchar(64) NOT NULL REFERENCES tenants(id),
    proposal_id       varchar(40) NOT NULL REFERENCES response_proposals(id),
    idempotency_key   varchar(80) NOT NULL,
    kind              varchar(10) NOT NULL CHECK (kind IN ('apply','rollback')),
    actor             varchar(200) NOT NULL,
    status            varchar(16) NOT NULL,
    pre_snapshot      jsonb,
    post_snapshot     jsonb,
    verification      jsonb,
    error             text,
    started_at        timestamptz NOT NULL DEFAULT now(),
    finished_at       timestamptz,
    UNIQUE (tenant_id, idempotency_key)
);
"""


def upgrade() -> None:
    app_role = os.environ.get("AEGIS_APP_DB_ROLE", "aegis_app")
    op.execute(DDL)
    for t in (
        "managed_resources",
        "response_proposals",
        "response_approvals",
        "response_executions",
    ):
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {t} "
            f"USING (tenant_id = current_setting('aegis.tenant_id', true)) "
            f"WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true))"
        )
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE ON managed_resources, response_proposals, "
        f"response_executions TO {app_role}"
    )
    op.execute(f"GRANT SELECT, INSERT ON response_approvals TO {app_role}")


def downgrade() -> None:
    raise NotImplementedError("forward-only migration")
