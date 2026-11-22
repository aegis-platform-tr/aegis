"""Alerts, incidents (with evidence timeline), rules and audit log."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from aegis import audit
from aegis.api.convert import alert_out, incident_out
from aegis.api.deps import require, tenant_session
from aegis.api.errors import ApiError
from aegis.api.pagination import DEFAULT_LIMIT, MAX_LIMIT, apply_keyset, encode_cursor
from aegis.api.schemas import (
    AlertOut,
    AuditOut,
    IncidentDetailOut,
    IncidentOut,
    IncidentPatchIn,
    Page,
    TimelineEntry,
)
from aegis.db import session_scope
from aegis.models import (
    AlertEvent,
    AuditLog,
    DetectionAlert,
    DetectionRule,
    Incident,
    IncidentAlert,
    IncidentTransition,
    SecurityEvent,
)
from aegis.security import Capability, Principal

router = APIRouter(prefix="/api/v1", tags=["cases"])

# Allowed incident state transitions. Reopen (resolved/closed -> investigating) is explicit.
TRANSITIONS: dict[str, frozenset[str]] = {
    "new": frozenset({"investigating", "contained", "resolved", "closed"}),
    "investigating": frozenset({"contained", "resolved", "closed"}),
    "contained": frozenset({"investigating", "resolved", "closed"}),
    "resolved": frozenset({"investigating", "closed"}),
    "closed": frozenset({"investigating"}),
}


# ---- Alerts -------------------------------------------------------------------------------


@router.get("/alerts", response_model=Page[AlertOut])
def list_alerts(
    principal: Principal = Depends(require(Capability.ALERTS_READ)),
    s: Session = Depends(tenant_session),
    cursor: str | None = None,
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    severity: str | None = Query(None, pattern="^(info|low|medium|high|critical)$"),
) -> Page[AlertOut]:
    conds = [DetectionAlert.tenant_id == principal.tenant_id]
    if severity:
        conds.append(DetectionAlert.severity == severity)
    total = s.execute(select(func.count()).select_from(DetectionAlert).where(*conds)).scalar_one()
    rows = list(
        s.scalars(
            apply_keyset(
                select(DetectionAlert).where(*conds),
                DetectionAlert.evaluated_at,
                DetectionAlert.id,
                cursor,
                limit,
            )
        ).all()
    )
    links: dict[str, str] = dict(
        s.execute(
            select(IncidentAlert.alert_id, IncidentAlert.incident_id).where(
                IncidentAlert.alert_id.in_([a.id for a in rows])
            )
        ).all()
    )
    nxt = (
        encode_cursor(rows[limit - 1].evaluated_at, rows[limit - 1].id)
        if len(rows) > limit
        else None
    )
    return Page[AlertOut](
        items=[alert_out(a, links.get(a.id)) for a in rows[:limit]], next_cursor=nxt, total=total
    )


@router.get("/alerts/{alert_id}", response_model=AlertOut)
def get_alert(
    alert_id: str,
    principal: Principal = Depends(require(Capability.ALERTS_READ)),
    s: Session = Depends(tenant_session),
) -> AlertOut:
    a = s.execute(
        select(DetectionAlert).where(
            DetectionAlert.tenant_id == principal.tenant_id, DetectionAlert.id == alert_id
        )
    ).scalar_one_or_none()
    if a is None:
        raise ApiError(404, "not_found", "Alert not found")
    incident_id = s.execute(
        select(IncidentAlert.incident_id).where(IncidentAlert.alert_id == a.id)
    ).scalar_one_or_none()
    event_ids = list(
        s.scalars(
            select(AlertEvent.event_id)
            .where(AlertEvent.alert_id == a.id)
            .order_by(AlertEvent.event_id)
        ).all()
    )
    return alert_out(a, incident_id, event_ids)


# ---- Incidents ----------------------------------------------------------------------------


def _alert_counts(s: Session, incident_ids: list[str]) -> dict[str, int]:
    if not incident_ids:
        return {}
    return dict(
        s.execute(
            select(IncidentAlert.incident_id, func.count())
            .where(IncidentAlert.incident_id.in_(incident_ids))
            .group_by(IncidentAlert.incident_id)
        ).all()
    )


@router.get("/incidents", response_model=Page[IncidentOut])
def list_incidents(
    principal: Principal = Depends(require(Capability.INCIDENTS_READ)),
    s: Session = Depends(tenant_session),
    cursor: str | None = None,
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    status: str | None = Query(None, pattern="^(new|investigating|contained|resolved|closed)$"),
    severity: str | None = Query(None, pattern="^(info|low|medium|high|critical)$"),
) -> Page[IncidentOut]:
    conds = [Incident.tenant_id == principal.tenant_id]
    if status:
        conds.append(Incident.status == status)
    if severity:
        conds.append(Incident.severity == severity)
    total = s.execute(select(func.count()).select_from(Incident).where(*conds)).scalar_one()
    rows = list(
        s.scalars(
            apply_keyset(
                select(Incident).where(*conds), Incident.updated_at, Incident.id, cursor, limit
            )
        ).all()
    )
    counts = _alert_counts(s, [i.id for i in rows[:limit]])
    nxt = (
        encode_cursor(rows[limit - 1].updated_at, rows[limit - 1].id) if len(rows) > limit else None
    )
    return Page[IncidentOut](
        items=[incident_out(i, counts.get(i.id, 0)) for i in rows[:limit]],
        next_cursor=nxt,
        total=total,
    )


def _load_incident(s: Session, tenant_id: str, incident_id: str) -> Incident:
    inc = s.execute(
        select(Incident).where(Incident.tenant_id == tenant_id, Incident.id == incident_id)
    ).scalar_one_or_none()
    if inc is None:
        raise ApiError(404, "not_found", "Incident not found")
    return inc


def _detail(s: Session, inc: Incident) -> IncidentDetailOut:
    alerts = list(
        s.scalars(
            select(DetectionAlert)
            .join(IncidentAlert, IncidentAlert.alert_id == DetectionAlert.id)
            .where(IncidentAlert.incident_id == inc.id)
            .order_by(DetectionAlert.first_event_at)
        ).all()
    )
    alert_ids = [a.id for a in alerts]
    links = s.execute(
        select(AlertEvent.alert_id, AlertEvent.event_id).where(AlertEvent.alert_id.in_(alert_ids))
    ).all()
    by_alert: dict[str, list[str]] = {}
    for aid, eid in links:
        by_alert.setdefault(aid, []).append(eid)
    events = list(
        s.scalars(
            select(SecurityEvent).where(SecurityEvent.id.in_({eid for _, eid in links}))
        ).all()
    )
    transitions = list(
        s.scalars(
            select(IncidentTransition)
            .where(IncidentTransition.incident_id == inc.id)
            .order_by(IncidentTransition.at, IncidentTransition.id)
        ).all()
    )

    timeline: list[TimelineEntry] = []
    for e in events:
        src = f" from {e.source_ip}" if e.source_ip else ""
        timeline.append(
            TimelineEntry(
                kind="event",
                at=e.occurred_at or e.observed_at,
                ref_id=e.id,
                origin=e.origin,
                summary=f"{e.event_category}/{e.event_type}{src}"
                + (f" on {e.asset_id}" if e.asset_id else ""),
                times={
                    "occurred_at": e.occurred_at,
                    "observed_at": e.observed_at,
                    "ingested_at": e.ingested_at,
                },
            )
        )
    for a in alerts:
        timeline.append(
            TimelineEntry(
                kind="alert",
                at=a.last_event_at,
                ref_id=a.id,
                origin=a.origin,
                summary=f"Alert {a.rule_id} r{a.rule_revision}: {a.event_count} events "
                f"(severity {a.severity})",
                times={
                    "window_start": a.window_start,
                    "window_end": a.window_end,
                    "evaluated_at": a.evaluated_at,
                },
            )
        )
    for t in transitions:
        timeline.append(
            TimelineEntry(
                kind="transition",
                at=t.at,
                ref_id=str(t.id),
                summary=f"{t.from_status or '∅'} → {t.to_status} by {t.actor}: {t.reason}",
                times={"recorded_at": t.at},
            )
        )
    order = {"event": 0, "alert": 1, "transition": 2}
    timeline.sort(key=lambda x: (x.at, order[x.kind], x.ref_id))

    base = incident_out(inc, len(alerts))
    return IncidentDetailOut(
        **base.model_dump(),
        alerts=[alert_out(a, inc.id, sorted(by_alert.get(a.id, []))) for a in alerts],
        timeline=timeline,
    )


@router.get("/incidents/{incident_id}", response_model=IncidentDetailOut)
def get_incident(
    incident_id: str,
    principal: Principal = Depends(require(Capability.INCIDENTS_READ)),
    s: Session = Depends(tenant_session),
) -> IncidentDetailOut:
    return _detail(s, _load_incident(s, principal.tenant_id, incident_id))


@router.patch("/incidents/{incident_id}", response_model=IncidentDetailOut)
def transition_incident(
    incident_id: str,
    body: IncidentPatchIn,
    request: Request,
    principal: Principal = Depends(require(Capability.INCIDENTS_UPDATE)),
) -> IncidentDetailOut:
    with session_scope(tenant_id=principal.tenant_id) as s:
        inc = _load_incident(s, principal.tenant_id, incident_id)
        if body.status not in TRANSITIONS[inc.status]:
            raise ApiError(
                409,
                "invalid_transition",
                f"Cannot move incident from {inc.status} to {body.status}",
            )
        # Optimistic concurrency: the UPDATE only succeeds if the version is unchanged.
        res = s.execute(
            update(Incident)
            .where(Incident.id == inc.id, Incident.version == body.version)
            .values(status=body.status, version=Incident.version + 1, updated_at=func.now())
            .returning(Incident.version)
        ).scalar_one_or_none()
        if res is None:
            raise ApiError(
                409, "version_conflict", "Incident was modified by someone else; reload and retry"
            )
        s.add(
            IncidentTransition(
                tenant_id=principal.tenant_id,
                incident_id=inc.id,
                from_status=inc.status,
                to_status=body.status,
                actor=principal.subject,
                reason=body.reason,
            )
        )
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.subject,
            action="incident.transition",
            outcome="success",
            target_type="incident",
            target_id=inc.id,
            request_id=request.state.request_id,
            details={"from": inc.status, "to": body.status, "version": res},
        )
        s.flush()
        s.expire_all()
        return _detail(s, _load_incident(s, principal.tenant_id, incident_id))


# ---- Rules and audit ----------------------------------------------------------------------


@router.get("/rules")
def list_rules(
    _: Principal = Depends(require(Capability.RULES_READ)),
    s: Session = Depends(tenant_session),
) -> list[dict[str, Any]]:
    rows = s.scalars(select(DetectionRule).order_by(DetectionRule.id, DetectionRule.revision)).all()
    return [
        {
            "rule_id": r.id,
            "revision": r.revision,
            "name": r.name,
            "status": r.status,
            "severity": r.severity,
            "confidence": float(r.confidence),
            "description": r.description,
            "definition": r.definition,
            "mitre": r.mitre,
            "author": r.author,
            "created_at": r.created_at,
        }
        for r in rows
    ]


@router.get("/audit", response_model=Page[AuditOut])
def list_audit(
    principal: Principal = Depends(require(Capability.AUDIT_READ)),
    s: Session = Depends(tenant_session),
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
) -> Page[AuditOut]:
    conds = [AuditLog.tenant_id == principal.tenant_id]
    total = s.execute(select(func.count()).select_from(AuditLog).where(*conds)).scalar_one()
    rows = s.scalars(select(AuditLog).where(*conds).order_by(AuditLog.id.desc()).limit(limit)).all()
    return Page[AuditOut](
        items=[
            AuditOut(
                id=r.id,
                actor=r.actor,
                action=r.action,
                target_type=r.target_type,
                target_id=r.target_id,
                outcome=r.outcome,
                request_id=r.request_id,
                details=r.details,
                at=r.at,
            )
            for r in rows
        ],
        next_cursor=None,
        total=total,
    )
