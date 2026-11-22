"""Tenant overview and system status. Counts come from the database; nothing is synthesized.
Unknown/missing data is reported as null with a reason, never as zero."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.agents import health_status
from aegis.api.deps import require, tenant_session
from aegis.models import (
    Agent,
    DetectionAlert,
    Incident,
    SecurityEvent,
    ServiceEvaluation,
    WorkItem,
)
from aegis.security import Capability, Principal

router = APIRouter(prefix="/api/v1", tags=["overview"])


def _group(s: Session, col: Any, model: Any, tenant: str, *extra: Any) -> dict[str, int]:
    rows = s.execute(
        select(col, func.count())
        .select_from(model)
        .where(model.tenant_id == tenant, *extra)
        .group_by(col)
    ).all()
    return {str(k): int(v) for k, v in rows}


def queue_status(s: Session, tenant: str) -> dict[str, Any]:
    by_status = _group(s, WorkItem.status, WorkItem, tenant)
    oldest = s.execute(
        select(func.min(WorkItem.created_at)).where(
            WorkItem.tenant_id == tenant, WorkItem.status == "pending"
        )
    ).scalar_one()
    lag = (datetime.now(UTC) - oldest).total_seconds() if oldest else 0.0
    retried = s.execute(
        select(func.count())
        .select_from(WorkItem)
        .where(WorkItem.tenant_id == tenant, WorkItem.attempts > 1)
    ).scalar_one()
    return {
        "pending": by_status.get("pending", 0),
        "done": by_status.get("done", 0),
        "dead": by_status.get("dead", 0),
        "retried": int(retried),
        "oldest_pending_age_seconds": round(lag, 1),
    }


@router.get("/overview")
def overview(
    principal: Principal = Depends(require(Capability.INCIDENTS_READ)),
    s: Session = Depends(tenant_session),
) -> dict[str, Any]:
    t = principal.tenant_id
    agents = s.scalars(select(Agent).where(Agent.tenant_id == t)).all()
    agent_health: dict[str, int] = {}
    for a in agents:
        h = health_status(a)
        agent_health[h] = agent_health.get(h, 0) + 1
    latest_minute = s.execute(
        select(func.max(ServiceEvaluation.minute)).where(ServiceEvaluation.tenant_id == t)
    ).scalar_one()
    events_total = s.execute(
        select(func.count()).select_from(SecurityEvent).where(SecurityEvent.tenant_id == t)
    ).scalar_one()
    return {
        "generated_at": datetime.now(UTC),
        "incidents_by_status": _group(s, Incident.status, Incident, t),
        "open_incidents_by_severity": _group(
            s,
            Incident.severity,
            Incident,
            t,
            Incident.status.in_(("new", "investigating", "contained")),
        ),
        "alerts_by_severity": _group(
            s, DetectionAlert.severity, DetectionAlert, t, DetectionAlert.suppressed.is_(False)
        ),
        "suppressed_alerts": s.execute(
            select(func.count())
            .select_from(DetectionAlert)
            .where(DetectionAlert.tenant_id == t, DetectionAlert.suppressed.is_(True))
        ).scalar_one(),
        "events_total": events_total,
        "events_by_origin": _group(s, SecurityEvent.origin, SecurityEvent, t),
        "last_event_ingested_at": s.execute(
            select(func.max(SecurityEvent.ingested_at)).where(SecurityEvent.tenant_id == t)
        ).scalar_one(),
        "agents": {"total": len(agents), "by_health": agent_health},
        "network": {
            "latest_evaluated_minute": latest_minute,
            "status": "no network telemetry yet" if latest_minute is None else "ok",
        },
        "pipeline": queue_status(s, t),
    }


@router.get("/system/status")
def system_status(
    principal: Principal = Depends(require(Capability.INCIDENTS_READ)),
    s: Session = Depends(tenant_session),
) -> dict[str, Any]:
    q = queue_status(s, principal.tenant_id)
    worker = (
        "idle"
        if q["pending"] == 0
        else "degraded: backlog older than 60 s"
        if q["oldest_pending_age_seconds"] > 60
        else "processing"
    )
    return {
        "components": [
            {"name": "api", "status": "ok", "required": True},
            {"name": "database", "status": "ok", "required": True},
            {
                "name": "worker",
                "status": worker,
                "required": True,
                "detail": "Inferred from queue age; the worker has no heartbeat endpoint yet.",
            },
            {
                "name": "ai_provider",
                "status": "optional (mock)",
                "required": False,
                "detail": "AI is non-essential; ingestion and detection run without it.",
            },
            {
                "name": "live_firewall_adapters",
                "status": "disabled",
                "required": False,
                "detail": "Response actions run in simulation; live writes are not supported.",
            },
        ],
        "queue": q,
    }
