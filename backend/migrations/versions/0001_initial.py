"""M1 initial schema: tenancy, identities, events, work queue, rules, alerts, incidents, audit.

Revision ID: 0001_initial
Revises:
"""

from __future__ import annotations

import os

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

TENANT_TABLES = [
    "security_events",
    "detection_alerts",
    "alert_events",
    "incidents",
    "incident_alerts",
    "incident_transitions",
]

DDL = """
CREATE TABLE tenants (
    id          varchar(64) PRIMARY KEY CHECK (id ~ '^[a-z0-9_\\-]{3,64}$'),
    name        varchar(200) NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id             uuid PRIMARY KEY,
    tenant_id      varchar(64) NOT NULL REFERENCES tenants(id),
    username       varchar(200) NOT NULL UNIQUE,
    password_hash  text NOT NULL,
    roles          varchar(64)[] NOT NULL,
    is_active      boolean NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_users_tenant_id ON users(tenant_id);

CREATE TABLE revoked_tokens (
    jti         varchar(64) PRIMARY KEY,
    expires_at  timestamptz NOT NULL
);

CREATE TABLE security_events (
    id                      varchar(40) PRIMARY KEY,
    tenant_id               varchar(64) NOT NULL REFERENCES tenants(id),
    producer_id             varchar(120) NOT NULL,
    source_adapter          varchar(64) NOT NULL,
    source_adapter_version  varchar(32) NOT NULL,
    source_native_id        varchar(200) NOT NULL,
    schema_version          varchar(16) NOT NULL,
    event_category          varchar(64) NOT NULL,
    event_type              varchar(64) NOT NULL,
    severity                varchar(16) CHECK (severity IN ('info','low','medium','high','critical')),
    occurred_at             timestamptz,
    observed_at             timestamptz NOT NULL,
    ingested_at             timestamptz NOT NULL DEFAULT now(),
    asset_id                varchar(120),
    source_ip               inet,
    destination_ip          inet,
    source_port             integer CHECK (source_port BETWEEN 0 AND 65535),
    destination_port        integer CHECK (destination_port BETWEEN 0 AND 65535),
    protocol                varchar(32),
    principal               varchar(200),
    attributes              jsonb NOT NULL DEFAULT '{}'::jsonb,
    origin                  varchar(16) NOT NULL CHECK (origin IN ('synthetic','observed')),
    raw_event_reference     varchar(300),
    provenance              jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT uq_security_events_source_identity
        UNIQUE (tenant_id, producer_id, source_adapter, source_native_id)
);
CREATE INDEX ix_events_tenant_ingested ON security_events (tenant_id, ingested_at DESC, id DESC);
CREATE INDEX ix_events_tenant_type_src_time ON security_events
    (tenant_id, event_category, event_type, source_ip, (COALESCE(occurred_at, observed_at)));

CREATE TABLE work_items (
    id          bigserial PRIMARY KEY,
    tenant_id   varchar(64) NOT NULL REFERENCES tenants(id),
    kind        varchar(32) NOT NULL,
    ref_id      varchar(40) NOT NULL,
    status      varchar(16) NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','done','dead')),
    attempts    integer NOT NULL DEFAULT 0,
    last_error  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_work_items_kind_ref UNIQUE (kind, ref_id)
);
CREATE INDEX ix_work_items_pending ON work_items (id) WHERE status = 'pending';

CREATE TABLE detection_rules (
    id           varchar(80) NOT NULL,
    revision     integer NOT NULL CHECK (revision > 0),
    name         varchar(200) NOT NULL,
    description  text NOT NULL,
    status       varchar(16) NOT NULL CHECK (status IN ('draft','active','disabled')),
    severity     varchar(16) NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    confidence   numeric(3,2) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    definition   jsonb NOT NULL,
    mitre        jsonb NOT NULL DEFAULT '[]'::jsonb,
    author       varchar(120) NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id, revision)
);

CREATE TABLE detection_alerts (
    id              varchar(40) PRIMARY KEY,
    tenant_id       varchar(64) NOT NULL REFERENCES tenants(id),
    rule_id         varchar(80) NOT NULL,
    rule_revision   integer NOT NULL,
    fingerprint     varchar(64) NOT NULL,
    title           varchar(300) NOT NULL,
    severity        varchar(16) NOT NULL,
    confidence      numeric(3,2) NOT NULL,
    group_key       jsonb NOT NULL,
    window_start    timestamptz NOT NULL,
    window_end      timestamptz NOT NULL,
    event_count     integer NOT NULL,
    first_event_at  timestamptz NOT NULL,
    last_event_at   timestamptz NOT NULL,
    explanation     text NOT NULL,
    mitre           jsonb NOT NULL DEFAULT '[]'::jsonb,
    origin          varchar(16) NOT NULL,
    evaluated_at    timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (rule_id, rule_revision) REFERENCES detection_rules(id, revision),
    CONSTRAINT uq_alerts_fingerprint UNIQUE (tenant_id, fingerprint)
);
CREATE INDEX ix_alerts_tenant_evaluated ON detection_alerts (tenant_id, evaluated_at DESC, id DESC);

CREATE TABLE alert_events (
    alert_id   varchar(40) NOT NULL REFERENCES detection_alerts(id),
    event_id   varchar(40) NOT NULL REFERENCES security_events(id),
    tenant_id  varchar(64) NOT NULL REFERENCES tenants(id),
    PRIMARY KEY (alert_id, event_id)
);
CREATE INDEX ix_alert_events_event ON alert_events (event_id);

CREATE TABLE incidents (
    id                varchar(40) PRIMARY KEY,
    tenant_id         varchar(64) NOT NULL REFERENCES tenants(id),
    title             varchar(300) NOT NULL,
    status            varchar(16) NOT NULL
                      CHECK (status IN ('new','investigating','contained','resolved','closed')),
    severity          varchar(16) NOT NULL,
    priority          varchar(4) NOT NULL,
    correlation_rule  varchar(80) NOT NULL,
    correlation_key   varchar(300) NOT NULL,
    origin            varchar(16) NOT NULL,
    version           integer NOT NULL DEFAULT 1,
    assigned_to       varchar(200),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    last_activity_at  timestamptz NOT NULL
);
CREATE INDEX ix_incidents_tenant_updated ON incidents (tenant_id, updated_at DESC, id DESC);
CREATE INDEX ix_incidents_open_key ON incidents (tenant_id, correlation_key)
    WHERE status IN ('new','investigating','contained');

CREATE TABLE incident_alerts (
    incident_id  varchar(40) NOT NULL REFERENCES incidents(id),
    alert_id     varchar(40) NOT NULL UNIQUE REFERENCES detection_alerts(id),
    tenant_id    varchar(64) NOT NULL REFERENCES tenants(id),
    linked_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (incident_id, alert_id)
);

CREATE TABLE incident_transitions (
    id           bigserial PRIMARY KEY,
    tenant_id    varchar(64) NOT NULL REFERENCES tenants(id),
    incident_id  varchar(40) NOT NULL REFERENCES incidents(id),
    from_status  varchar(16),
    to_status    varchar(16) NOT NULL,
    actor        varchar(200) NOT NULL,
    reason       text NOT NULL,
    at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_transitions_incident ON incident_transitions (incident_id, at);

CREATE TABLE audit_logs (
    id           bigserial PRIMARY KEY,
    tenant_id    varchar(64) REFERENCES tenants(id),
    actor        varchar(200) NOT NULL,
    action       varchar(80) NOT NULL,
    target_type  varchar(64),
    target_id    varchar(120),
    outcome      varchar(16) NOT NULL,
    request_id   varchar(64),
    details      jsonb NOT NULL DEFAULT '{}'::jsonb,
    at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_audit_tenant_at ON audit_logs (tenant_id, at DESC);

INSERT INTO detection_rules (id, revision, name, description, status, severity, confidence,
                             definition, mitre, author)
VALUES (
  'auth.bruteforce.source_asset', 1,
  'Repeated authentication failures from one source against one asset',
  'Counts login_failure events per (source_ip, asset_id) in a tumbling event-time window. '
  'Fires when the count reaches the threshold. Late events are re-counted into their bucket.',
  'active', 'high', 0.70,
  '{"kind": "threshold",
    "match": {"event_category": "authentication", "event_type": "login_failure"},
    "group_by": ["source_ip", "asset_id"],
    "window_seconds": 300,
    "threshold": 5,
    "time_field": "occurred_at_else_observed_at",
    "late_arrival": "recount_bucket"}'::jsonb,
  '[{"framework": "ATT&CK", "id": "T1110", "name": "Brute Force",
     "note": "Descriptive label only; does not imply a successful compromise."}]'::jsonb,
  'aegis-core'
);
"""


def upgrade() -> None:
    app_role = os.environ.get("AEGIS_APP_DB_ROLE", "aegis_app")
    op.execute(DDL)

    # Row-level security on every tenant-scoped data table.
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING (tenant_id = current_setting('aegis.tenant_id', true)) "
            f"WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true))"
        )
    # Audit rows may be written before a tenant is known (failed login with unknown user).
    op.execute("ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY audit_read ON audit_logs FOR SELECT "
        "USING (tenant_id = current_setting('aegis.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY audit_insert ON audit_logs FOR INSERT "
        "WITH CHECK (tenant_id IS NULL OR tenant_id = current_setting('aegis.tenant_id', true))"
    )

    # Least-privilege grants for the runtime role (it never owns tables, so RLS binds it).
    op.execute(f"GRANT USAGE ON SCHEMA public TO {app_role}")
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE ON tenants, users, work_items, detection_alerts, "
        f"incidents TO {app_role}"
    )
    # Normalized events and evidence links are immutable once written.
    op.execute(
        f"GRANT SELECT, INSERT ON security_events, alert_events, incident_alerts, "
        f"incident_transitions TO {app_role}"
    )
    op.execute(f"GRANT SELECT, INSERT, DELETE ON revoked_tokens TO {app_role}")
    op.execute(f"GRANT SELECT ON detection_rules, alembic_version TO {app_role}")
    # Audit log is append-only for the application: no UPDATE/DELETE.
    op.execute(f"GRANT SELECT, INSERT ON audit_logs TO {app_role}")
    op.execute(f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {app_role}")


def downgrade() -> None:
    op.execute(
        "DROP TABLE IF EXISTS audit_logs, incident_transitions, incident_alerts, incidents, "
        "alert_events, detection_alerts, detection_rules, work_items, security_events, "
        "revoked_tokens, users, tenants CASCADE"
    )
