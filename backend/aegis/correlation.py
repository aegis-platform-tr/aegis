"""Entity/time-window correlation of alerts into incidents (M1: one correlation rule).

An alert joins the open incident with the same correlation key whose last activity is within
the window; otherwise a new incident is created. A transaction-scoped advisory lock per
(tenant, key) prevents two workers from creating duplicate incidents concurrently.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from aegis.models import DetectionAlert, Incident, IncidentAlert, IncidentTransition

CORRELATION_RULE_ID = "corr.entity_window.v1"
CORRELATION_WINDOW = timedelta(hours=1)
OPEN_STATUSES = ("new", "investigating", "contained")
SEVERITY_TO_PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P5"}
SYSTEM_ACTOR = "system:correlation"


def correlation_key(alert: DetectionAlert) -> str:
    if "service_key" in alert.group_key:
        return f"service:{alert.group_key['service_key']}"
    for field_name in ("source_ip", "asset_id", "principal"):
        if field_name in alert.group_key:
            return f"{field_name}:{alert.group_key[field_name]}"
    return f"rule:{alert.rule_id}"


def correlate_alert(session: Session, alert_id: str) -> str:
    """Attach the alert to an incident and return the incident id. Idempotent."""
    alert = session.execute(
        select(DetectionAlert).where(DetectionAlert.id == alert_id)
    ).scalar_one()
    existing = session.execute(
        select(IncidentAlert.incident_id).where(IncidentAlert.alert_id == alert_id)
    ).scalar_one_or_none()
    if existing:
        _touch(session, existing, alert)
        return existing

    key = correlation_key(alert)
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
        {"k": f"{alert.tenant_id}|{key}"},
    )
    incident_id = session.execute(
        select(Incident.id)
        .where(
            Incident.tenant_id == alert.tenant_id,
            Incident.correlation_key == key,
            Incident.status.in_(OPEN_STATUSES),
            Incident.last_activity_at >= alert.first_event_at - CORRELATION_WINDOW,
        )
        .order_by(Incident.last_activity_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    if incident_id is None:
        incident_id = f"inc_{uuid.uuid4().hex}"
        session.add(
            Incident(
                id=incident_id,
                tenant_id=alert.tenant_id,
                title=alert.title,
                status="new",
                severity=alert.severity,
                priority=SEVERITY_TO_PRIORITY.get(alert.severity, "P3"),
                correlation_rule=CORRELATION_RULE_ID,
                correlation_key=key,
                origin=alert.origin,
                version=1,
                last_activity_at=alert.last_event_at,
            )
        )
        session.flush()
        session.add(
            IncidentTransition(
                tenant_id=alert.tenant_id,
                incident_id=incident_id,
                from_status=None,
                to_status="new",
                actor=SYSTEM_ACTOR,
                reason=f"Created by {CORRELATION_RULE_ID} for {key} from alert {alert.id}",
            )
        )
    session.execute(
        pg_insert(IncidentAlert)
        .values(incident_id=incident_id, alert_id=alert.id, tenant_id=alert.tenant_id)
        .on_conflict_do_nothing()
    )
    _touch(session, incident_id, alert)
    return incident_id


def _touch(session: Session, incident_id: str, alert: DetectionAlert) -> None:
    session.execute(
        update(Incident)
        .where(Incident.id == incident_id)
        .values(last_activity_at=func.greatest(Incident.last_activity_at, alert.last_event_at))
    )
