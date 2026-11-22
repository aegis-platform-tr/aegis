"""M2: agent enrollment, identities, credentials and heartbeats.

Revision ID: 0002_agents
Revises: 0001_initial
"""

from __future__ import annotations

import os

from alembic import op

revision = "0002_agents"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

DDL = """
CREATE TABLE enrollment_tokens (
    token_hash   char(64) PRIMARY KEY,
    tenant_id    varchar(64) NOT NULL REFERENCES tenants(id),
    created_by   varchar(200) NOT NULL,
    label        varchar(200) NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz,
    used_by_agent varchar(40)
);

CREATE TABLE agents (
    id               varchar(40) PRIMARY KEY,
    tenant_id        varchar(64) NOT NULL REFERENCES tenants(id),
    hostname         varchar(200) NOT NULL,
    platform         varchar(16) NOT NULL CHECK (platform IN ('linux','windows','darwin')),
    agent_version    varchar(32) NOT NULL,
    status           varchar(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    enrolled_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz,
    last_heartbeat   jsonb NOT NULL DEFAULT '{}'::jsonb,
    clock_skew_ms    integer,
    revoked_at       timestamptz,
    revoked_by       varchar(200),
    revoke_reason    text
);
CREATE INDEX ix_agents_tenant ON agents (tenant_id, enrolled_at DESC, id DESC);

-- Looked up before the tenant is known (agent authentication), so not RLS-scoped.
CREATE TABLE agent_credentials (
    credential_hash  char(64) PRIMARY KEY,
    agent_id         varchar(40) NOT NULL REFERENCES agents(id),
    tenant_id        varchar(64) NOT NULL REFERENCES tenants(id),
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    revoked_at       timestamptz
);
CREATE INDEX ix_agent_credentials_agent ON agent_credentials (agent_id);
"""


def upgrade() -> None:
    app_role = os.environ.get("AEGIS_APP_DB_ROLE", "aegis_app")
    op.execute(DDL)
    op.execute("ALTER TABLE agents ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE agents FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON agents "
        "USING (tenant_id = current_setting('aegis.tenant_id', true)) "
        "WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true))"
    )
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE ON agents, enrollment_tokens, agent_credentials TO {app_role}"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS agent_credentials, agents, enrollment_tokens CASCADE")
