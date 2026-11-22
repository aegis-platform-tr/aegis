"""ORM -> API model conversion."""

from __future__ import annotations

from aegis.api.schemas import AlertOut, EventOut, IncidentOut
from aegis.models import DetectionAlert, Incident, SecurityEvent


def event_out(e: SecurityEvent) -> EventOut:
    return EventOut(
        event_id=e.id,
        schema_version=e.schema_version,
        event_category=e.event_category,
        event_type=e.event_type,
        severity=e.severity,
        occurred_at=e.occurred_at,
        observed_at=e.observed_at,
        ingested_at=e.ingested_at,
        source={
            "adapter": e.source_adapter,
            "adapter_version": e.source_adapter_version,
            "native_id": e.source_native_id,
        },
        producer_id=e.producer_id,
        asset_id=e.asset_id,
        source_ip=str(e.source_ip) if e.source_ip else None,
        destination_ip=str(e.destination_ip) if e.destination_ip else None,
        source_port=e.source_port,
        destination_port=e.destination_port,
        protocol=e.protocol,
        principal=e.principal,
        attributes=e.attributes,
        origin=e.origin,
        raw_event_reference=e.raw_event_reference,
        provenance=e.provenance,
    )


def alert_out(
    a: DetectionAlert, incident_id: str | None = None, event_ids: list[str] | None = None
) -> AlertOut:
    return AlertOut(
        alert_id=a.id,
        rule_id=a.rule_id,
        rule_revision=a.rule_revision,
        title=a.title,
        severity=a.severity,
        confidence=float(a.confidence),
        group_key=a.group_key,
        window_start=a.window_start,
        window_end=a.window_end,
        event_count=a.event_count,
        first_event_at=a.first_event_at,
        last_event_at=a.last_event_at,
        evaluated_at=a.evaluated_at,
        explanation=a.explanation,
        mitre=a.mitre,
        origin=a.origin,
        suppressed=a.suppressed,
        suppression_id=a.suppression_id,
        evidence_quality=a.evidence_quality,
        incident_id=incident_id,
        event_ids=event_ids,
    )


def incident_out(i: Incident, alert_count: int) -> IncidentOut:
    return IncidentOut(
        incident_id=i.id,
        title=i.title,
        status=i.status,
        severity=i.severity,
        priority=i.priority,
        correlation_rule=i.correlation_rule,
        correlation_key=i.correlation_key,
        origin=i.origin,
        version=i.version,
        assigned_to=i.assigned_to,
        created_at=i.created_at,
        updated_at=i.updated_at,
        last_activity_at=i.last_activity_at,
        alert_count=alert_count,
    )
