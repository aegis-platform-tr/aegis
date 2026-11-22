"""M3: tenant rules and lifecycle, suppressions, incident notes/assignment, service baselines.

Revision ID: 0003_detection_m3
Revises: 0002_agents
"""

from __future__ import annotations

import os

from alembic import op

revision = "0003_detection_m3"
down_revision = "0002_agents"
branch_labels = None
depends_on = None

TENANT_POLICY = (
    "CREATE POLICY tenant_isolation ON {t} "
    "USING (tenant_id = current_setting('aegis.tenant_id', true)) "
    "WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true))"
)

DDL = """
ALTER TABLE detection_rules
    ADD COLUMN tenant_id varchar(64) REFERENCES tenants(id),
    ADD COLUMN schema_compat varchar(16) NOT NULL DEFAULT '1.0',
    ADD COLUMN evidence_fields jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN change_reason text NOT NULL DEFAULT 'initial revision',
    ADD COLUMN published_at timestamptz,
    ADD COLUMN published_by varchar(200);
ALTER TABLE detection_rules DROP CONSTRAINT detection_rules_status_check;
ALTER TABLE detection_rules ADD CONSTRAINT detection_rules_status_check
    CHECK (status IN ('draft','active','retired','disabled'));
UPDATE detection_rules SET status = 'active', published_at = now(), published_by = 'aegis-core'
    WHERE status = 'active';
CREATE UNIQUE INDEX uq_rules_one_active ON detection_rules (id) WHERE status = 'active';

CREATE TABLE rule_tenant_settings (
    tenant_id   varchar(64) NOT NULL REFERENCES tenants(id),
    rule_id     varchar(80) NOT NULL,
    enabled     boolean NOT NULL,
    changed_by  varchar(200) NOT NULL,
    reason      text NOT NULL,
    changed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, rule_id)
);

CREATE TABLE suppressions (
    id            varchar(40) PRIMARY KEY,
    tenant_id     varchar(64) NOT NULL REFERENCES tenants(id),
    rule_id       varchar(80),
    entity_field  varchar(64) NOT NULL CHECK (entity_field IN ('source_ip','destination_ip','asset_id','principal')),
    entity_value  varchar(200) NOT NULL,
    reason        text NOT NULL,
    created_by    varchar(200) NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz,
    revoked_by    varchar(200),
    CHECK (expires_at > created_at)
);
CREATE INDEX ix_suppressions_lookup ON suppressions (tenant_id, entity_field, entity_value);

ALTER TABLE detection_alerts
    ADD COLUMN suppressed boolean NOT NULL DEFAULT false,
    ADD COLUMN suppression_id varchar(40) REFERENCES suppressions(id),
    ADD COLUMN evidence_quality varchar(16) NOT NULL DEFAULT 'direct'
        CHECK (evidence_quality IN ('direct','aggregate','inferred'));

CREATE TABLE incident_notes (
    id           bigserial PRIMARY KEY,
    tenant_id    varchar(64) NOT NULL REFERENCES tenants(id),
    incident_id  varchar(40) NOT NULL REFERENCES incidents(id),
    kind         varchar(32) NOT NULL
                 CHECK (kind IN ('note','assignment','containment_verification','closure_reason')),
    author       varchar(200) NOT NULL,
    body         text NOT NULL CHECK (length(body) BETWEEN 1 AND 10000),
    at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_incident_notes ON incident_notes (incident_id, at);

-- Per-minute service aggregates for baselines (event-time minutes).
CREATE TABLE service_minutes (
    tenant_id     varchar(64) NOT NULL REFERENCES tenants(id),
    service_key   varchar(120) NOT NULL,
    minute        timestamptz NOT NULL,
    requests      integer NOT NULL DEFAULT 0,
    errors        integer NOT NULL DEFAULT 0,
    bytes         bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, service_key, minute)
);
CREATE TABLE service_minute_sources (
    tenant_id    varchar(64) NOT NULL REFERENCES tenants(id),
    service_key  varchar(120) NOT NULL,
    minute       timestamptz NOT NULL,
    source_ip    inet NOT NULL,
    requests     integer NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, service_key, minute, source_ip)
);
CREATE TABLE service_baseline_state (
    tenant_id               varchar(64) NOT NULL REFERENCES tenants(id),
    service_key             varchar(120) NOT NULL,
    max_seen_minute         timestamptz NOT NULL,
    last_evaluated_minute   timestamptz,
    late_events             integer NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, service_key)
);
CREATE TABLE service_evaluations (
    tenant_id            varchar(64) NOT NULL REFERENCES tenants(id),
    service_key          varchar(120) NOT NULL,
    minute               timestamptz NOT NULL,
    classification       varchar(24) NOT NULL CHECK (classification IN
                         ('warming_up','normal','expected_burst','anomaly','missing_telemetry')),
    requests             integer NOT NULL,
    unique_sources       integer NOT NULL,
    error_rate           numeric(6,4) NOT NULL,
    baseline_median      numeric(12,2),
    baseline_mad         numeric(12,2),
    volume_score         numeric(10,2),
    new_source_fraction  numeric(6,4),
    alert_id             varchar(40) REFERENCES detection_alerts(id),
    evaluated_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, service_key, minute)
);

INSERT INTO detection_rules (id, revision, name, description, status, severity, confidence,
    definition, mitre, author, evidence_fields, change_reason, published_at, published_by)
VALUES
('ids.suricata.high_severity', 1,
 'Suricata high-severity signature',
 'Raises one alert per (source, destination, signature) per 5-minute window when Suricata '
 'reports a severity-1 (high) alert. The sensor signature, not AEGIS, determines the match.',
 'active', 'high', 0.60,
 '{"kind": "threshold",
   "match": {"event_category": "ids", "event_type": "ids_alert", "severity_in": ["high", "critical"]},
   "group_by": ["source_ip", "destination_ip", "attributes.signature_id"],
   "window_seconds": 300, "threshold": 1,
   "time_field": "occurred_at_else_observed_at", "late_arrival": "recount_bucket"}'::jsonb,
 '[]'::jsonb, 'aegis-core', '["attributes.signature", "attributes.signature_id", "attributes.category"]'::jsonb,
 'initial revision', now(), 'aegis-core'),
('auth.windows.account_lockout', 1,
 'Windows account lockout',
 'One alert per locked-out account per 15 minutes (Security event 4740).',
 'active', 'medium', 0.80,
 '{"kind": "threshold",
   "match": {"event_category": "authentication", "event_type": "account_lockout"},
   "group_by": ["principal", "asset_id"], "window_seconds": 900, "threshold": 1,
   "time_field": "occurred_at_else_observed_at", "late_arrival": "recount_bucket"}'::jsonb,
 '[]'::jsonb, 'aegis-core', '["principal", "attributes.computer"]'::jsonb,
 'initial revision', now(), 'aegis-core'),
('ddos.service_baseline', 1,
 'Service request-rate anomaly with new-source surge',
 'Per-service, per-minute baseline (median and MAD over the previous 30 minutes, 15-minute '
 'warm-up). A minute is anomalous when volume is far above baseline AND most sources are new '
 'AND (unique sources surge or error rate is high). High volume from known sources with low '
 'errors is classified expected_burst and does not alert. Low-confidence signal pending '
 'corroboration; single vantage point.',
 'active', 'high', 0.50,
 '{"kind": "baseline", "metric": "requests_per_minute",
   "event_types": ["http_request", "flow"],
   "history_minutes": 30, "warmup_minutes": 15, "grace_minutes": 1,
   "volume_score_threshold": 6.0, "new_source_fraction_threshold": 0.5,
   "source_surge_ratio": 5.0, "error_rate_threshold": 0.2,
   "burst_known_source_fraction": 0.7}'::jsonb,
 '[{"framework": "ATT&CK", "id": "T1498", "name": "Network Denial of Service",
    "note": "Descriptive label only; a traffic anomaly is not proof of an attack."}]'::jsonb,
 'aegis-core', '["service_key", "requests", "unique_sources", "error_rate"]'::jsonb,
 'initial revision', now(), 'aegis-core');
"""


def upgrade() -> None:
    app_role = os.environ.get("AEGIS_APP_DB_ROLE", "aegis_app")
    op.execute(DDL)
    # Rules: built-ins (tenant_id NULL) are readable by all tenants and writable by none.
    op.execute("ALTER TABLE detection_rules ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE detection_rules FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY rules_read ON detection_rules FOR SELECT "
        "USING (tenant_id IS NULL OR tenant_id = current_setting('aegis.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY rules_insert ON detection_rules FOR INSERT "
        "WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY rules_update ON detection_rules FOR UPDATE "
        "USING (tenant_id = current_setting('aegis.tenant_id', true)) "
        "WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true))"
    )
    for t in (
        "rule_tenant_settings",
        "suppressions",
        "incident_notes",
        "service_minutes",
        "service_minute_sources",
        "service_baseline_state",
        "service_evaluations",
    ):
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(TENANT_POLICY.format(t=t))
    op.execute(f"GRANT INSERT, UPDATE ON detection_rules TO {app_role}")
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE ON rule_tenant_settings, suppressions, service_minutes, "
        f"service_minute_sources, service_baseline_state, service_evaluations TO {app_role}"
    )
    op.execute(f"GRANT SELECT, INSERT ON incident_notes TO {app_role}")
    op.execute(f"GRANT UPDATE (assigned_to) ON incidents TO {app_role}")
    op.execute(f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {app_role}")


def downgrade() -> None:
    raise NotImplementedError("forward-only migration; restore from backup to roll back")
