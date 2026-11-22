"""Deterministic, declarative rule evaluation (M1 supports the 'threshold' kind only).

Rules cannot carry code, shell commands or network calls: a definition is validated
against ThresholdRule before use and unknown kinds are refused.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from aegis.models import AlertEvent, DetectionAlert, DetectionRule, SecurityEvent

GROUPABLE_FIELDS = ("source_ip", "destination_ip", "asset_id", "principal", "destination_port")


class RuleMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_category: str
    event_type: str


class ThresholdRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["threshold"]
    match: RuleMatch
    group_by: list[
        Literal["source_ip", "destination_ip", "asset_id", "principal", "destination_port"]
    ] = Field(min_length=1, max_length=4)
    window_seconds: int = Field(ge=10, le=86_400)
    threshold: int = Field(ge=2, le=100_000)
    time_field: Literal["occurred_at_else_observed_at"]
    late_arrival: Literal["recount_bucket"]


def event_time(event: SecurityEvent) -> datetime:
    return event.occurred_at or event.observed_at


def _bucket(ts: datetime, window_seconds: int) -> tuple[datetime, datetime]:
    epoch = int(ts.timestamp())
    start = epoch - (epoch % window_seconds)
    start_dt = datetime.fromtimestamp(start, tz=UTC)
    return start_dt, start_dt + timedelta(seconds=window_seconds)


def fingerprint(rule_id: str, revision: int, group: dict[str, str], window_start: datetime) -> str:
    material = json.dumps(
        {"r": rule_id, "v": revision, "g": group, "w": window_start.isoformat()}, sort_keys=True
    )
    return hashlib.sha256(material.encode()).hexdigest()


def active_rules(session: Session) -> list[tuple[DetectionRule, ThresholdRule]]:
    """Latest active revision of each rule."""
    latest = (
        select(DetectionRule.id, func.max(DetectionRule.revision).label("rev"))
        .where(DetectionRule.status == "active")
        .group_by(DetectionRule.id)
        .subquery()
    )
    rows = session.scalars(
        select(DetectionRule).join(
            latest,
            (DetectionRule.id == latest.c.id) & (DetectionRule.revision == latest.c.rev),
        )
    ).all()
    return [(r, ThresholdRule.model_validate(r.definition)) for r in rows]


def evaluate_event(session: Session, event: SecurityEvent) -> list[str]:
    """Evaluate one event against active rules. Returns ids of alerts it contributes to.
    Idempotent: re-running for the same event changes nothing."""
    alert_ids: list[str] = []
    for rule, spec in active_rules(session):
        if (event.event_category, event.event_type) != (
            spec.match.event_category,
            spec.match.event_type,
        ):
            continue
        group: dict[str, str] = {}
        for field_name in spec.group_by:
            value = getattr(event, field_name)
            if value is None:
                break
            group[field_name] = str(value)
        else:
            alert_id = _evaluate_threshold(session, rule, spec, event, group)
            if alert_id:
                alert_ids.append(alert_id)
    return alert_ids


def _evaluate_threshold(
    session: Session,
    rule: DetectionRule,
    spec: ThresholdRule,
    event: SecurityEvent,
    group: dict[str, str],
) -> str | None:
    window_start, window_end = _bucket(event_time(event), spec.window_seconds)
    ts = func.coalesce(SecurityEvent.occurred_at, SecurityEvent.observed_at)
    conditions = [
        SecurityEvent.tenant_id == event.tenant_id,
        SecurityEvent.event_category == spec.match.event_category,
        SecurityEvent.event_type == spec.match.event_type,
        ts >= window_start,
        ts < window_end,
    ]
    for field_name, value in group.items():
        conditions.append(getattr(SecurityEvent, field_name) == value)

    matching = session.execute(
        select(SecurityEvent.id, ts.label("ts"), SecurityEvent.origin)
        .where(*conditions)
        .order_by(ts, SecurityEvent.id)
    ).all()
    if len(matching) < spec.threshold:
        return None

    fp = fingerprint(rule.id, rule.revision, group, window_start)
    origin = "synthetic" if any(m.origin == "synthetic" for m in matching) else "observed"
    group_desc = ", ".join(f"{k}={v}" for k, v in group.items())
    session.execute(
        pg_insert(DetectionAlert)
        .values(
            id=f"alr_{uuid.uuid4().hex}",
            tenant_id=event.tenant_id,
            rule_id=rule.id,
            rule_revision=rule.revision,
            fingerprint=fp,
            title=f"{rule.name} ({group_desc})",
            severity=rule.severity,
            confidence=rule.confidence,
            group_key=group,
            window_start=window_start,
            window_end=window_end,
            event_count=0,
            first_event_at=matching[0].ts,
            last_event_at=matching[-1].ts,
            explanation="",
            mitre=rule.mitre,
            origin=origin,
        )
        .on_conflict_do_nothing(constraint="uq_alerts_fingerprint")
    )
    alert = session.execute(
        select(DetectionAlert).where(
            DetectionAlert.tenant_id == event.tenant_id, DetectionAlert.fingerprint == fp
        )
    ).scalar_one()

    session.execute(
        pg_insert(AlertEvent)
        .values(
            [
                {"alert_id": alert.id, "event_id": m.id, "tenant_id": event.tenant_id}
                for m in matching
            ]
        )
        .on_conflict_do_nothing()
    )
    count = session.execute(
        select(func.count()).select_from(AlertEvent).where(AlertEvent.alert_id == alert.id)
    ).scalar_one()
    explanation = (
        f"{count} {spec.match.event_type} events with {group_desc} in the event-time window "
        f"[{window_start.isoformat()}, {window_end.isoformat()}) reached threshold "
        f"{spec.threshold} (rule {rule.id} r{rule.revision}). "
        f"Severity, confidence ({Decimal(rule.confidence)}) and the ATT&CK label are rule "
        f"metadata; they describe the pattern, not a confirmed compromise."
    )
    session.execute(
        update(DetectionAlert)
        .where(DetectionAlert.id == alert.id)
        .values(
            event_count=count,
            first_event_at=func.least(DetectionAlert.first_event_at, matching[0].ts),
            last_event_at=func.greatest(DetectionAlert.last_event_at, matching[-1].ts),
            explanation=explanation,
            updated_at=func.now(),
        )
    )
    return alert.id
