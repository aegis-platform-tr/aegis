"""Detection rule lifecycle (draft -> test -> publish -> retire/rollback), suppressions, and
network service baselines. Every state change is audited."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import desc, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from aegis import audit
from aegis.api.deps import require, tenant_session
from aegis.api.errors import ApiError
from aegis.api.routes_events import _load_pack
from aegis.config import Settings, get_settings
from aegis.contracts import EventIn
from aegis.db import session_scope
from aegis.detection import ThresholdRule, evaluate_offline, parse_definition
from aegis.models import (
    DetectionRule,
    RuleTenantSetting,
    ServiceBaselineState,
    ServiceEvaluation,
    Suppression,
)
from aegis.security import Capability, Principal

router = APIRouter(prefix="/api/v1", tags=["detection"])

Slug = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.\-]{2,40}$")]
Reason = Annotated[str, Field(min_length=3, max_length=1000)]
MAX_TEST_EVENTS = 5000


class MitreRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    framework: Literal["ATT&CK", "ATLAS"]
    id: str = Field(pattern=r"^(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?)$")
    name: str = Field(max_length=120)
    note: str = Field(default="Descriptive label only; not proof of compromise.", max_length=300)


class RuleBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=3, max_length=4000)
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    definition: dict[str, Any]
    mitre: list[MitreRef] = Field(default_factory=list, max_length=5)
    evidence_fields: list[str] = Field(default_factory=list, max_length=20)
    change_reason: Reason


class NewRule(RuleBody):
    slug: Slug


class TestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fixture: str | None = None
    events: list[dict[str, Any]] | None = Field(default=None, max_length=MAX_TEST_EVENTS)


class ReasonBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Reason


class SuppressionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str | None = Field(default=None, max_length=80)
    entity_field: Literal["source_ip", "destination_ip", "asset_id", "principal"]
    entity_value: str = Field(min_length=1, max_length=200)
    reason: Reason
    expires_in_hours: int = Field(ge=1, le=720)


def _validate_definition(raw: dict[str, Any]) -> None:
    try:
        parse_definition(raw)
    except ValidationError as exc:
        fields = [
            {
                "field": "definition." + ".".join(str(p) for p in e["loc"]),
                "code": e["type"],
                "message": e["msg"],
            }
            for e in exc.errors(include_input=False, include_url=False)
        ]
        raise ApiError(
            422, "invalid_rule_definition", "Rule definition is invalid", fields
        ) from exc


def _rule_view(r: DetectionRule, tenant_disabled: set[str]) -> dict[str, Any]:
    return {
        "rule_id": r.id,
        "revision": r.revision,
        "name": r.name,
        "status": r.status,
        "scope": "built-in" if r.tenant_id is None else "tenant",
        "enabled_for_tenant": r.id not in tenant_disabled,
        "severity": r.severity,
        "confidence": float(r.confidence),
        "description": r.description,
        "definition": r.definition,
        "mitre": r.mitre,
        "evidence_fields": r.evidence_fields,
        "schema_compat": r.schema_compat,
        "author": r.author,
        "change_reason": r.change_reason,
        "created_at": r.created_at,
        "published_at": r.published_at,
        "published_by": r.published_by,
    }


def _disabled(s: Session, tenant_id: str) -> set[str]:
    return set(
        s.scalars(
            select(RuleTenantSetting.rule_id).where(
                RuleTenantSetting.tenant_id == tenant_id, RuleTenantSetting.enabled.is_(False)
            )
        ).all()
    )


@router.get("/rules")
def list_rules(
    principal: Principal = Depends(require(Capability.RULES_READ)),
    s: Session = Depends(tenant_session),
) -> list[dict[str, Any]]:
    rows = s.scalars(
        select(DetectionRule).order_by(DetectionRule.id, desc(DetectionRule.revision))
    ).all()
    disabled = _disabled(s, principal.tenant_id)
    return [_rule_view(r, disabled) for r in rows]


def _load_rule(s: Session, rule_id: str, revision: int) -> DetectionRule:
    r = s.get(DetectionRule, (rule_id, revision))
    if r is None:
        raise ApiError(404, "not_found", "Rule revision not found")
    return r


def _own_rule_or_403(rule: DetectionRule, principal: Principal) -> None:
    if rule.tenant_id != principal.tenant_id:
        raise ApiError(
            403,
            "builtin_rule_immutable",
            "Built-in rules cannot be edited; disable it for your tenant instead",
        )


@router.post("/rules", status_code=201)
def create_rule(
    body: NewRule,
    request: Request,
    principal: Principal = Depends(require(Capability.RULES_WRITE)),
) -> dict[str, Any]:
    _validate_definition(body.definition)
    rule_id = f"{principal.tenant_id}.{body.slug}"
    with session_scope(tenant_id=principal.tenant_id) as s:
        if s.execute(select(DetectionRule.id).where(DetectionRule.id == rule_id)).first():
            raise ApiError(409, "rule_exists", "Rule id already exists; add a revision instead")
        rule = _new_revision(s, principal, rule_id, 1, body)
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.subject,
            action="rule.create",
            outcome="success",
            target_type="rule",
            target_id=f"{rule_id}@1",
            request_id=request.state.request_id,
            details={"reason": body.change_reason},
        )
        return _rule_view(rule, set())


@router.post("/rules/{rule_id}/revisions", status_code=201)
def add_revision(
    rule_id: str,
    body: RuleBody,
    request: Request,
    principal: Principal = Depends(require(Capability.RULES_WRITE)),
) -> dict[str, Any]:
    _validate_definition(body.definition)
    with session_scope(tenant_id=principal.tenant_id) as s:
        latest = s.execute(
            select(DetectionRule)
            .where(DetectionRule.id == rule_id)
            .order_by(desc(DetectionRule.revision))
            .limit(1)
        ).scalar_one_or_none()
        if latest is None:
            raise ApiError(404, "not_found", "Rule not found")
        _own_rule_or_403(latest, principal)
        rule = _new_revision(s, principal, rule_id, latest.revision + 1, body)
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.subject,
            action="rule.revise",
            outcome="success",
            target_type="rule",
            target_id=f"{rule_id}@{rule.revision}",
            request_id=request.state.request_id,
            details={"reason": body.change_reason},
        )
        return _rule_view(rule, set())


def _new_revision(
    s: Session, p: Principal, rule_id: str, rev: int, body: RuleBody
) -> DetectionRule:
    rule = DetectionRule(
        id=rule_id,
        revision=rev,
        tenant_id=p.tenant_id,
        name=body.name,
        description=body.description,
        status="draft",
        severity=body.severity,
        confidence=Decimal(str(body.confidence)),
        definition=body.definition,
        mitre=[m.model_dump() for m in body.mitre],
        author=p.subject,
        evidence_fields=body.evidence_fields,
        change_reason=body.change_reason,
        schema_compat="1.0",
    )
    s.add(rule)
    s.flush()
    return rule


@router.post("/rules/{rule_id}/revisions/{revision}/test")
def test_rule(
    rule_id: str,
    revision: int,
    body: TestBody,
    principal: Principal = Depends(require(Capability.RULES_READ)),
    s: Session = Depends(tenant_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Dry-run a (draft or published) rule revision against labeled fixture data.
    Nothing is persisted: no events, alerts or incidents are created."""
    rule = _load_rule(s, rule_id, revision)
    spec = parse_definition(rule.definition)
    if not isinstance(spec, ThresholdRule):
        raise ApiError(
            422,
            "unsupported_for_test",
            "Offline testing supports threshold rules; baseline rules are evaluated "
            "with the baseline fixture through the pipeline",
        )
    if (body.fixture is None) == (body.events is None):
        raise ApiError(422, "validation_failed", "Provide exactly one of fixture or events")
    raw = _load_pack(settings, body.fixture)["events"] if body.fixture else body.events or []
    events: list[dict[str, Any]] = []
    invalid = 0
    for item in raw[:MAX_TEST_EVENTS]:
        try:
            events.append(EventIn.model_validate(item).model_dump(mode="python"))
        except ValidationError:
            invalid += 1
    for e in events:
        e["source_ip"] = str(e["source_ip"]) if e.get("source_ip") else None
        e["destination_ip"] = str(e["destination_ip"]) if e.get("destination_ip") else None
        e["severity"] = e["severity"].value if e.get("severity") else None
    hits = evaluate_offline(spec, events)
    return {
        "rule_id": rule.id,
        "revision": rule.revision,
        "status": rule.status,
        "events_evaluated": len(events),
        "events_invalid": invalid,
        "would_alert": len(hits),
        "hits": [
            {
                "group_key": h.group_key,
                "window_start": h.window_start,
                "window_end": h.window_end,
                "event_count": len(h.event_indexes),
                "native_ids": [events[i]["source"]["native_id"] for i in h.event_indexes],
            }
            for h in hits
        ],
        "persisted": False,
    }


@router.post("/rules/{rule_id}/revisions/{revision}/publish")
def publish(
    rule_id: str,
    revision: int,
    body: ReasonBody,
    request: Request,
    principal: Principal = Depends(require(Capability.RULES_WRITE)),
) -> dict[str, Any]:
    """Activate a revision. Publishing an older revision is a rollback."""
    with session_scope(tenant_id=principal.tenant_id) as s:
        rule = _load_rule(s, rule_id, revision)
        _own_rule_or_403(rule, principal)
        _validate_definition(rule.definition)
        previous = s.execute(
            select(DetectionRule.revision).where(
                DetectionRule.id == rule_id, DetectionRule.status == "active"
            )
        ).scalar_one_or_none()
        s.execute(
            update(DetectionRule)
            .where(DetectionRule.id == rule_id, DetectionRule.status == "active")
            .values(status="retired")
        )
        s.flush()
        rule.status = "active"
        rule.published_at = datetime.now(UTC)
        rule.published_by = principal.subject
        action = "rule.rollback" if previous is not None and previous > revision else "rule.publish"
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.subject,
            action=action,
            outcome="success",
            target_type="rule",
            target_id=f"{rule_id}@{revision}",
            request_id=request.state.request_id,
            details={"reason": body.reason, "previous_active_revision": previous},
        )
        s.flush()
        return _rule_view(rule, set())


@router.post("/rules/{rule_id}/disable")
def disable_rule(
    rule_id: str,
    body: ReasonBody,
    request: Request,
    principal: Principal = Depends(require(Capability.RULES_WRITE)),
) -> dict[str, Any]:
    return _set_enabled(rule_id, False, body.reason, request, principal)


@router.post("/rules/{rule_id}/enable")
def enable_rule(
    rule_id: str,
    body: ReasonBody,
    request: Request,
    principal: Principal = Depends(require(Capability.RULES_WRITE)),
) -> dict[str, Any]:
    return _set_enabled(rule_id, True, body.reason, request, principal)


def _set_enabled(
    rule_id: str, enabled: bool, reason: str, request: Request, principal: Principal
) -> dict[str, Any]:
    with session_scope(tenant_id=principal.tenant_id) as s:
        latest = s.execute(
            select(DetectionRule)
            .where(DetectionRule.id == rule_id)
            .order_by(desc(DetectionRule.revision))
            .limit(1)
        ).scalar_one_or_none()
        if latest is None:
            raise ApiError(404, "not_found", "Rule not found")
        if latest.tenant_id is None:
            s.execute(
                pg_insert(RuleTenantSetting)
                .values(
                    tenant_id=principal.tenant_id,
                    rule_id=rule_id,
                    enabled=enabled,
                    changed_by=principal.subject,
                    reason=reason,
                )
                .on_conflict_do_update(
                    index_elements=["tenant_id", "rule_id"],
                    set_={
                        "enabled": enabled,
                        "changed_by": principal.subject,
                        "reason": reason,
                        "changed_at": func.now(),
                    },
                )
            )
        elif not enabled:
            s.execute(
                update(DetectionRule)
                .where(DetectionRule.id == rule_id, DetectionRule.status == "active")
                .values(status="retired")
            )
        else:
            raise ApiError(
                409, "publish_required", "Tenant rules are enabled by publishing a revision"
            )
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.subject,
            action="rule.enable" if enabled else "rule.disable",
            outcome="success",
            target_type="rule",
            target_id=rule_id,
            request_id=request.state.request_id,
            details={"reason": reason},
        )
    return {"rule_id": rule_id, "enabled_for_tenant": enabled}


# ---- Suppressions -------------------------------------------------------------------------


def _supp_view(x: Suppression) -> dict[str, Any]:
    now = datetime.now(UTC)
    state = "revoked" if x.revoked_at else ("expired" if x.expires_at <= now else "active")
    return {
        "suppression_id": x.id,
        "rule_id": x.rule_id,
        "entity_field": x.entity_field,
        "entity_value": x.entity_value,
        "reason": x.reason,
        "created_by": x.created_by,
        "created_at": x.created_at,
        "expires_at": x.expires_at,
        "state": state,
        "revoked_at": x.revoked_at,
        "revoked_by": x.revoked_by,
    }


@router.get("/suppressions")
def list_suppressions(
    principal: Principal = Depends(require(Capability.ALERTS_READ)),
    s: Session = Depends(tenant_session),
) -> list[dict[str, Any]]:
    rows = s.scalars(
        select(Suppression)
        .where(Suppression.tenant_id == principal.tenant_id)
        .order_by(desc(Suppression.created_at))
        .limit(500)
    ).all()
    return [_supp_view(x) for x in rows]


@router.post("/suppressions", status_code=201)
def create_suppression(
    body: SuppressionIn,
    request: Request,
    principal: Principal = Depends(require(Capability.SUPPRESSIONS_MANAGE)),
) -> dict[str, Any]:
    with session_scope(tenant_id=principal.tenant_id) as s:
        x = Suppression(
            id=f"sup_{uuid.uuid4().hex}",
            tenant_id=principal.tenant_id,
            rule_id=body.rule_id,
            entity_field=body.entity_field,
            entity_value=body.entity_value,
            reason=body.reason,
            created_by=principal.subject,
            expires_at=datetime.now(UTC) + timedelta(hours=body.expires_in_hours),
        )
        s.add(x)
        s.flush()
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.subject,
            action="suppression.create",
            outcome="success",
            target_type="suppression",
            target_id=x.id,
            request_id=request.state.request_id,
            details=json.loads(body.model_dump_json()),
        )
        s.refresh(x)
        return _supp_view(x)


@router.post("/suppressions/{suppression_id}/revoke")
def revoke_suppression(
    suppression_id: str,
    body: ReasonBody,
    request: Request,
    principal: Principal = Depends(require(Capability.SUPPRESSIONS_MANAGE)),
) -> dict[str, Any]:
    with session_scope(tenant_id=principal.tenant_id) as s:
        x = s.execute(
            select(Suppression).where(
                Suppression.tenant_id == principal.tenant_id, Suppression.id == suppression_id
            )
        ).scalar_one_or_none()
        if x is None:
            raise ApiError(404, "not_found", "Suppression not found")
        x.revoked_at = datetime.now(UTC)
        x.revoked_by = principal.subject
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.subject,
            action="suppression.revoke",
            outcome="success",
            target_type="suppression",
            target_id=x.id,
            request_id=request.state.request_id,
            details={"reason": body.reason},
        )
        s.flush()
        return _supp_view(x)


# ---- Network service baselines ------------------------------------------------------------


@router.get("/network/services")
def list_services(
    principal: Principal = Depends(require(Capability.NETWORK_READ)),
    s: Session = Depends(tenant_session),
) -> list[dict[str, Any]]:
    states = s.scalars(
        select(ServiceBaselineState)
        .where(ServiceBaselineState.tenant_id == principal.tenant_id)
        .order_by(ServiceBaselineState.service_key)
    ).all()
    out = []
    for st in states:
        counts = dict(
            s.execute(
                select(ServiceEvaluation.classification, func.count())
                .where(
                    ServiceEvaluation.tenant_id == principal.tenant_id,
                    ServiceEvaluation.service_key == st.service_key,
                )
                .group_by(ServiceEvaluation.classification)
            )
            .tuples()
            .all()
        )
        out.append(
            {
                "service_key": st.service_key,
                "max_seen_minute": st.max_seen_minute,
                "last_evaluated_minute": st.last_evaluated_minute,
                "late_events": st.late_events,
                "classification_counts": counts,
                "coverage": "single sensor vantage point; event-time minutes",
            }
        )
    return out


@router.get("/network/services/{service_key}/minutes")
def service_minutes(
    service_key: str,
    principal: Principal = Depends(require(Capability.NETWORK_READ)),
    s: Session = Depends(tenant_session),
    limit: int = Query(240, ge=1, le=1440),
) -> dict[str, Any]:
    rows = list(
        s.scalars(
            select(ServiceEvaluation)
            .where(
                ServiceEvaluation.tenant_id == principal.tenant_id,
                ServiceEvaluation.service_key == service_key,
            )
            .order_by(desc(ServiceEvaluation.minute))
            .limit(limit)
        ).all()
    )
    rows.reverse()
    return {
        "service_key": service_key,
        "timezone": "UTC",
        "aggregation": "1 minute (event time)",
        "units": {
            "requests": "requests/minute",
            "error_rate": "fraction",
            "new_source_fraction": "fraction of requests",
        },
        "minutes": [
            {
                "minute": r.minute,
                "classification": r.classification,
                "requests": r.requests,
                "unique_sources": r.unique_sources,
                "error_rate": float(r.error_rate),
                "baseline_median": float(r.baseline_median)
                if r.baseline_median is not None
                else None,
                "volume_score": float(r.volume_score) if r.volume_score is not None else None,
                "new_source_fraction": float(r.new_source_fraction)
                if r.new_source_fraction is not None
                else None,
                "alert_id": r.alert_id,
            }
            for r in rows
        ],
    }
