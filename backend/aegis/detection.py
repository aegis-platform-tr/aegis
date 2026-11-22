"""Deterministic, declarative rule evaluation.

Rule kinds: ``threshold`` (evaluated per event, here) and ``baseline`` (evaluated per service
minute, in aegis.baselines). Rules are data validated against bounded schemas: they cannot carry
code, shell commands or network calls, and unknown kinds or fields are refused.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter
from sqlalchemy import ColumnElement, and_, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from aegis.models import (
    AlertEvent,
    DetectionAlert,
    DetectionRule,
    RuleTenantSetting,
    SecurityEvent,
    Suppression,
)

TOP_LEVEL_FIELDS = ("source_ip", "destination_ip", "asset_id", "principal", "destination_port")
GroupField = Annotated[
    str,
    Field(
        pattern=r"^(source_ip|destination_ip|asset_id|principal|destination_port|"
        r"attributes\.[a-z][a-z0-9_]{0,39})$"
    ),
]
Severity = Literal["info", "low", "medium", "high", "critical"]


class RuleMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_category: str = Field(pattern=r"^[a-z0-9_.\-]{1,64}$")
    event_type: str = Field(pattern=r"^[a-z0-9_.\-]{1,64}$")
    severity_in: list[Severity] | None = Field(default=None, min_length=1, max_length=5)


class ThresholdRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["threshold"]
    match: RuleMatch
    group_by: list[GroupField] = Field(min_length=1, max_length=4)
    window_seconds: int = Field(ge=10, le=86_400)
    threshold: int = Field(ge=1, le=100_000)
    time_field: Literal["occurred_at_else_observed_at"]
    late_arrival: Literal["recount_bucket"]


class BaselineRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["baseline"]
    metric: Literal["requests_per_minute"]
    event_types: list[Literal["http_request", "flow"]] = Field(min_length=1, max_length=2)
    history_minutes: int = Field(ge=10, le=1440)
    warmup_minutes: int = Field(ge=5, le=1440)
    grace_minutes: int = Field(ge=0, le=30)
    volume_score_threshold: float = Field(gt=0, le=100)
    new_source_fraction_threshold: float = Field(gt=0, le=1)
    source_surge_ratio: float = Field(gt=1, le=1000)
    error_rate_threshold: float = Field(gt=0, le=1)
    burst_known_source_fraction: float = Field(gt=0, le=1)


RuleDefinition = Annotated[ThresholdRule | BaselineRule, Field(discriminator="kind")]
RULE_DEFINITION = TypeAdapter(RuleDefinition)


def parse_definition(raw: dict[str, Any]) -> ThresholdRule | BaselineRule:
    return RULE_DEFINITION.validate_python(raw)


def event_time(event: SecurityEvent) -> datetime:
    return event.occurred_at or event.observed_at


def bucket(ts: datetime, window_seconds: int) -> tuple[datetime, datetime]:
    epoch = int(ts.timestamp())
    start = datetime.fromtimestamp(epoch - (epoch % window_seconds), tz=UTC)
    return start, start + timedelta(seconds=window_seconds)


def fingerprint(rule_id: str, revision: int, group: dict[str, str], window_start: datetime) -> str:
    material = json.dumps(
        {"r": rule_id, "v": revision, "g": group, "w": window_start.isoformat()}, sort_keys=True
    )
    return hashlib.sha256(material.encode()).hexdigest()


def _field_value(source: Any, name: str) -> str | None:
    """Read a group field from an ORM event or a plain dict."""
    if name.startswith("attributes."):
        attrs = source.get("attributes", {}) if isinstance(source, dict) else source.attributes
        value = (attrs or {}).get(name.split(".", 1)[1])
    else:
        value = source.get(name) if isinstance(source, dict) else getattr(source, name)
    if value is None or isinstance(value, dict | list):
        return None
    return str(value)


def group_key(source: Any, spec: ThresholdRule) -> dict[str, str] | None:
    out: dict[str, str] = {}
    for name in spec.group_by:
        v = _field_value(source, name)
        if v is None:
            return None
        out[name] = v
    return out


def _get(source: Any, key: str) -> Any:
    return source.get(key) if isinstance(source, dict) else getattr(source, key)


def matches(source: Any, spec: ThresholdRule) -> bool:
    if (_get(source, "event_category"), _get(source, "event_type")) != (
        spec.match.event_category,
        spec.match.event_type,
    ):
        return False
    severity = _get(source, "severity")
    return not (spec.match.severity_in and severity not in spec.match.severity_in)


def active_rules(
    session: Session, tenant_id: str
) -> list[tuple[DetectionRule, ThresholdRule | BaselineRule]]:
    """Active revision of each rule visible to the tenant, minus tenant-disabled built-ins."""
    disabled = select(RuleTenantSetting.rule_id).where(
        RuleTenantSetting.tenant_id == tenant_id, RuleTenantSetting.enabled.is_(False)
    )
    rows = session.scalars(
        select(DetectionRule)
        .where(
            DetectionRule.status == "active",
            or_(DetectionRule.tenant_id.is_(None), DetectionRule.tenant_id == tenant_id),
            DetectionRule.id.not_in(disabled),
        )
        .order_by(DetectionRule.id)
    ).all()
    return [(r, parse_definition(r.definition)) for r in rows]


@dataclass
class AlertOutcome:
    alert_id: str
    suppressed: bool


def evaluate_event(session: Session, event: SecurityEvent) -> list[AlertOutcome]:
    """Evaluate one event against active threshold rules. Idempotent."""
    out: list[AlertOutcome] = []
    for rule, spec in active_rules(session, event.tenant_id):
        if not isinstance(spec, ThresholdRule) or not matches(event, spec):
            continue
        group = group_key(event, spec)
        if group is None:
            continue
        outcome = _evaluate_threshold(session, rule, spec, event, group)
        if outcome:
            out.append(outcome)
    return out


def _sql_condition(name: str, value: str) -> ColumnElement[bool]:
    if name.startswith("attributes."):
        attr: ColumnElement[bool] = SecurityEvent.attributes[name.split(".", 1)[1]].astext == value
        return attr
    if name == "destination_port":
        return SecurityEvent.destination_port == int(value)
    column: ColumnElement[Any] = getattr(SecurityEvent, name)
    condition: ColumnElement[bool] = column == value
    return condition


def _evaluate_threshold(
    session: Session,
    rule: DetectionRule,
    spec: ThresholdRule,
    event: SecurityEvent,
    group: dict[str, str],
) -> AlertOutcome | None:
    window_start, window_end = bucket(event_time(event), spec.window_seconds)
    ts = func.coalesce(SecurityEvent.occurred_at, SecurityEvent.observed_at)
    conditions: list[ColumnElement[bool]] = [
        SecurityEvent.tenant_id == event.tenant_id,
        SecurityEvent.event_category == spec.match.event_category,
        SecurityEvent.event_type == spec.match.event_type,
        ts >= window_start,
        ts < window_end,
    ]
    if spec.match.severity_in:
        conditions.append(SecurityEvent.severity.in_(spec.match.severity_in))
    conditions += [_sql_condition(k, v) for k, v in group.items()]
    matching = session.execute(
        select(SecurityEvent.id, ts.label("ts"), SecurityEvent.origin)
        .where(and_(*conditions))
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
    unit = "event" if spec.threshold == 1 else "events"
    explanation = (
        f"{count} {spec.match.event_type} {unit} with {group_desc} in the event-time window "
        f"[{window_start.isoformat()}, {window_end.isoformat()}) reached threshold "
        f"{spec.threshold} (rule {rule.id} r{rule.revision}). Severity and confidence "
        f"({float(rule.confidence):.2f}) are rule metadata; any ATT&CK label describes the "
        f"pattern, not a confirmed compromise."
    )
    suppression = find_suppression(session, event.tenant_id, rule.id, group, event)
    if suppression is None and alert.suppression_id:
        # Once suppressed, an alert stays suppressed and keeps explaining why.
        suppression = session.get(Suppression, alert.suppression_id)
    values: dict[str, Any] = {
        "event_count": count,
        "first_event_at": func.least(DetectionAlert.first_event_at, matching[0].ts),
        "last_event_at": func.greatest(DetectionAlert.last_event_at, matching[-1].ts),
        "explanation": explanation,
        "updated_at": func.now(),
    }
    if suppression is not None:
        values["suppressed"] = True
        values["suppression_id"] = alert.suppression_id or suppression.id
        values["explanation"] = explanation + (
            f" Suppressed by {suppression.id} ({suppression.entity_field}="
            f"{suppression.entity_value}, until {suppression.expires_at.isoformat()}): "
            f"{suppression.reason}"
        )
    session.execute(update(DetectionAlert).where(DetectionAlert.id == alert.id).values(**values))
    return AlertOutcome(alert.id, bool(alert.suppressed or suppression is not None))


def find_suppression(
    session: Session, tenant_id: str, rule_id: str, group: dict[str, str], event: Any
) -> Suppression | None:
    """Active, unexpired suppression matching the alert entity (from group key or event)."""
    candidates: list[ColumnElement[bool]] = []
    for name in ("source_ip", "destination_ip", "asset_id", "principal"):
        value = group.get(name) or _field_value(event, name)
        if value:
            candidates.append(
                and_(Suppression.entity_field == name, Suppression.entity_value == value)
            )
    if not candidates:
        return None
    return session.execute(
        select(Suppression)
        .where(
            Suppression.tenant_id == tenant_id,
            Suppression.revoked_at.is_(None),
            Suppression.expires_at > func.now(),
            or_(Suppression.rule_id.is_(None), Suppression.rule_id == rule_id),
            or_(*candidates),
        )
        .order_by(Suppression.created_at)
        .limit(1)
    ).scalar_one_or_none()


# ---- Offline evaluation (draft rule testing against fixtures; no persistence) -------------


@dataclass
class OfflineHit:
    group_key: dict[str, str]
    window_start: datetime
    window_end: datetime
    event_indexes: list[int] = field(default_factory=list)


def evaluate_offline(spec: ThresholdRule, events: list[dict[str, Any]]) -> list[OfflineHit]:
    """Pure evaluation of a threshold rule over normalized event dicts (same semantics as the
    database path: tumbling event-time windows, group keys, threshold)."""
    buckets: dict[str, OfflineHit] = {}
    for i, ev in enumerate(events):
        if not matches(ev, spec):
            continue
        g = group_key(ev, spec)
        if g is None:
            continue
        raw_ts = ev.get("occurred_at") or ev.get("observed_at")
        ts = raw_ts if isinstance(raw_ts, datetime) else datetime.fromisoformat(str(raw_ts))
        start, end = bucket(ts, spec.window_seconds)
        key = json.dumps({"g": g, "w": start.isoformat()}, sort_keys=True)
        buckets.setdefault(key, OfflineHit(g, start, end)).event_indexes.append(i)
    return sorted(
        (h for h in buckets.values() if len(h.event_indexes) >= spec.threshold),
        key=lambda h: (h.window_start, json.dumps(h.group_key, sort_keys=True)),
    )
