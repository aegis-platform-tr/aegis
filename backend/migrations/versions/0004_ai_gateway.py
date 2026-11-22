"""M4: AI gateway tenant policies and request audit records.

Revision ID: 0004_ai_gateway
Revises: 0003_detection_m3
"""

from __future__ import annotations

import os

from alembic import op

revision = "0004_ai_gateway"
down_revision = "0003_detection_m3"
branch_labels = None
depends_on = None

DDL = """
CREATE TABLE ai_tenant_policies (
    tenant_id              varchar(64) PRIMARY KEY REFERENCES tenants(id),
    revision               integer NOT NULL DEFAULT 1,
    provider               varchar(32) NOT NULL DEFAULT 'mock'
                           CHECK (provider IN ('mock', 'cloud_disabled', 'none')),
    allow_tools            boolean NOT NULL DEFAULT true,
    allow_write_proposals  boolean NOT NULL DEFAULT false,
    share_principals       boolean NOT NULL DEFAULT false,
    max_requests_per_day   integer NOT NULL DEFAULT 500 CHECK (max_requests_per_day BETWEEN 0 AND 100000),
    updated_by             varchar(200) NOT NULL DEFAULT 'system',
    updated_at             timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ai_requests (
    id               varchar(40) PRIMARY KEY,
    tenant_id        varchar(64) NOT NULL REFERENCES tenants(id),
    actor            varchar(200) NOT NULL,
    capability       varchar(40) NOT NULL,
    policy_version   varchar(40) NOT NULL,
    decision         varchar(24) NOT NULL CHECK (decision IN
                     ('allow','flag','redact','deny','require_review','dependency_unavailable')),
    status           varchar(24) NOT NULL,
    input_checks     jsonb NOT NULL DEFAULT '[]'::jsonb,
    output_checks    jsonb NOT NULL DEFAULT '[]'::jsonb,
    provider         varchar(32),
    model            varchar(80),
    provider_called  boolean NOT NULL DEFAULT false,
    tool_calls       jsonb NOT NULL DEFAULT '[]'::jsonb,
    latency_ms       integer,
    cost_units       integer NOT NULL DEFAULT 0,
    prompt_sha256    char(64),
    prompt_chars     integer NOT NULL DEFAULT 0,
    evidence_ids     jsonb NOT NULL DEFAULT '[]'::jsonb,
    error            varchar(300),
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_ai_requests_tenant ON ai_requests (tenant_id, created_at DESC);
"""


def upgrade() -> None:
    app_role = os.environ.get("AEGIS_APP_DB_ROLE", "aegis_app")
    op.execute(DDL)
    for t in ("ai_tenant_policies", "ai_requests"):
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {t} "
            f"USING (tenant_id = current_setting('aegis.tenant_id', true)) "
            f"WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true))"
        )
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON ai_tenant_policies TO {app_role}")
    op.execute(f"GRANT SELECT, INSERT ON ai_requests TO {app_role}")


def downgrade() -> None:
    raise NotImplementedError("forward-only migration")
