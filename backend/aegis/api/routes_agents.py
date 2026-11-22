"""Agent management (human-authenticated) and agent-facing endpoints (agent credential)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis import agents as agent_svc
from aegis import audit
from aegis.api.deps import require, tenant_session
from aegis.api.errors import ApiError
from aegis.api.routes_events import _summarize
from aegis.config import Settings, get_settings
from aegis.contracts import EventBatchIn
from aegis.db import session_scope, set_tenant
from aegis.ingestion import ingest_items
from aegis.models import Agent
from aegis.security import Capability, Principal

router = APIRouter(prefix="/api/v1", tags=["agents"])
_bearer = HTTPBearer(auto_error=False)

Hostname = Annotated[str, Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9._\-]+$")]
Version = Annotated[
    str, Field(min_length=5, max_length=32, pattern=r"^\d+\.\d+\.\d+(-[A-Za-z0-9.]+)?$")
]


class EnrollmentTokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(min_length=1, max_length=200)
    ttl_minutes: int = Field(default=60, ge=5, le=1440)


class EnrollIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enrollment_token: str = Field(min_length=10, max_length=200)
    hostname: Hostname
    platform: Literal["linux", "windows", "darwin"]
    agent_version: Version


class SourceStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(max_length=100)
    type: str = Field(max_length=40)
    status: Literal["ok", "waiting", "error", "paused", "permission_denied"]
    lag_seconds: float | None = Field(default=None, ge=0)
    last_read_at: datetime | None = None
    cursor_resets: int = Field(default=0, ge=0)
    error: str | None = Field(default=None, max_length=300)


class HeartbeatIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_version: Version
    config_version: int = Field(ge=1)
    agent_time: datetime
    queue_depth: int = Field(ge=0)
    spool_bytes: int = Field(ge=0)
    spool_full: bool = False
    dropped_events: int = Field(ge=0)
    quarantined_lines: int = Field(ge=0)
    sent_events: int = Field(ge=0)
    sources: list[SourceStatus] = Field(default_factory=list, max_length=50)


# ---- Human-facing management --------------------------------------------------------------


def _agent_view(a: Agent) -> dict[str, Any]:
    hb = a.last_heartbeat or {}
    return {
        "agent_id": a.id,
        "hostname": a.hostname,
        "platform": a.platform,
        "agent_version": a.agent_version,
        "status": a.status,
        "health": agent_svc.health_status(a),
        "enrolled_at": a.enrolled_at,
        "last_seen_at": a.last_seen_at,
        "clock_skew_ms": a.clock_skew_ms,
        "queue_depth": hb.get("queue_depth"),
        "spool_full": hb.get("spool_full"),
        "dropped_events": hb.get("dropped_events"),
        "quarantined_lines": hb.get("quarantined_lines"),
        "sent_events": hb.get("sent_events"),
        "sources": hb.get("sources", []),
        "revoked_at": a.revoked_at,
        "revoke_reason": a.revoke_reason,
    }


@router.post("/agents/enrollment-tokens", status_code=201)
def create_enrollment_token(
    body: EnrollmentTokenIn,
    request: Request,
    principal: Principal = Depends(require(Capability.AGENTS_MANAGE)),
) -> dict[str, Any]:
    with session_scope(tenant_id=principal.tenant_id) as s:
        token, expires = agent_svc.create_enrollment_token(
            s,
            tenant_id=principal.tenant_id,
            created_by=principal.subject,
            label=body.label,
            ttl=timedelta(minutes=body.ttl_minutes),
        )
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.subject,
            action="agent.enrollment_token.create",
            outcome="success",
            request_id=request.state.request_id,
            details={"label": body.label, "expires_at": expires.isoformat()},
        )
    # Shown exactly once; only its digest is stored.
    return {"enrollment_token": token, "expires_at": expires, "single_use": True}


@router.get("/agents")
def list_agents(
    principal: Principal = Depends(require(Capability.AGENTS_READ)),
    s: Session = Depends(tenant_session),
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    rows = s.scalars(
        select(Agent)
        .where(Agent.tenant_id == principal.tenant_id)
        .order_by(Agent.enrolled_at.desc(), Agent.id.desc())
        .limit(limit)
    ).all()
    total = s.execute(
        select(func.count()).select_from(Agent).where(Agent.tenant_id == principal.tenant_id)
    ).scalar_one()
    return {"items": [_agent_view(a) for a in rows], "total": total, "next_cursor": None}


@router.post("/agents/{agent_id}/revoke")
def revoke_agent(
    agent_id: str,
    request: Request,
    body: dict[str, str],
    principal: Principal = Depends(require(Capability.AGENTS_MANAGE)),
) -> dict[str, Any]:
    reason = str(body.get("reason", "")).strip()
    if not 3 <= len(reason) <= 500:
        raise ApiError(422, "validation_failed", "A reason (3-500 chars) is required")
    with session_scope(tenant_id=principal.tenant_id) as s:
        agent = s.execute(
            select(Agent).where(Agent.tenant_id == principal.tenant_id, Agent.id == agent_id)
        ).scalar_one_or_none()
        if agent is None:
            raise ApiError(404, "not_found", "Agent not found")
        agent_svc.revoke(s, agent=agent, actor=principal.subject, reason=reason)
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.subject,
            action="agent.revoke",
            outcome="success",
            target_type="agent",
            target_id=agent_id,
            request_id=request.state.request_id,
            details={"reason": reason},
        )
        s.flush()
        return _agent_view(agent)


# ---- Agent-facing -------------------------------------------------------------------------


def get_agent(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> agent_svc.AgentPrincipal:
    if creds is None:
        raise ApiError(401, "unauthenticated", "Agent credential required")
    with session_scope() as s:
        try:
            principal = agent_svc.authenticate(s, creds.credentials)
        except agent_svc.AgentAuthError as exc:
            raise ApiError(
                401, "invalid_agent_credential", "Agent credential is invalid, expired or revoked"
            ) from exc
    return principal


@router.post("/agent/enroll", status_code=201)
def enroll(body: EnrollIn, request: Request) -> dict[str, Any]:
    denied: agent_svc.EnrollmentError | None = None
    out: dict[str, Any] = {}
    with session_scope() as s:
        try:
            agent, credential, expires = agent_svc.enroll(
                s,
                token=body.enrollment_token,
                hostname=body.hostname,
                platform=body.platform,
                agent_version=body.agent_version,
            )
        except agent_svc.EnrollmentError as exc:
            audit.record(
                s,
                tenant_id=None,
                actor="anonymous:agent-enroll",
                action="agent.enroll",
                outcome="denied",
                request_id=request.state.request_id,
            )
            denied = exc
        else:
            denied = None
            audit.record(
                s,
                tenant_id=agent.tenant_id,
                actor=f"agent:{agent.id}",
                action="agent.enroll",
                outcome="success",
                target_type="agent",
                target_id=agent.id,
                request_id=request.state.request_id,
                details={"hostname": body.hostname, "platform": body.platform},
            )
            out = {
                "agent_id": agent.id,
                "tenant_id": agent.tenant_id,
                "credential": credential,
                "credential_expires_at": expires,
            }
    if denied is not None:
        raise ApiError(401, "enrollment_denied", str(denied))
    return out


@router.post("/agent/heartbeat")
def heartbeat(
    body: HeartbeatIn, principal: agent_svc.AgentPrincipal = Depends(get_agent)
) -> dict[str, Any]:
    with session_scope(tenant_id=principal.tenant_id) as s:
        agent = agent_svc.record_heartbeat(
            s, principal, body.model_dump(mode="json"), body.agent_time
        )
        skew = agent.clock_skew_ms
    version = agent_svc.parse_version(body.agent_version)
    supported = version is not None and version >= agent_svc.MIN_SUPPORTED_AGENT_VERSION
    rotate_after = principal.expires_at - timedelta(days=7)
    return {
        "server_time": datetime.now(UTC),
        "clock_skew_ms": skew,
        "accepted_schema_versions": agent_svc.ACCEPTED_SCHEMA_VERSIONS,
        "agent_version_supported": supported,
        "rotate_credential": datetime.now(UTC) >= rotate_after,
    }


@router.post("/agent/rotate")
def rotate(
    request: Request, principal: agent_svc.AgentPrincipal = Depends(get_agent)
) -> dict[str, Any]:
    with session_scope(tenant_id=principal.tenant_id) as s:
        credential, expires = agent_svc.rotate(s, principal)
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.producer_id,
            action="agent.rotate",
            outcome="success",
            target_type="agent",
            target_id=principal.agent_id,
            request_id=request.state.request_id,
        )
    return {"credential": credential, "credential_expires_at": expires}


@router.post("/agent/events")
def agent_events(
    body: EventBatchIn,
    request: Request,
    principal: agent_svc.AgentPrincipal = Depends(get_agent),
    settings: Settings = Depends(get_settings),
) -> Any:
    if len(body.events) > settings.max_batch_items:
        raise ApiError(413, "batch_too_large", f"Batch exceeds {settings.max_batch_items} items")
    with session_scope(tenant_id=principal.tenant_id) as s:
        set_tenant(s, principal.tenant_id)
        results = ingest_items(
            s,
            tenant_id=principal.tenant_id,
            producer_id=principal.producer_id,
            items=body.events,
            ingest_channel="agent",
        )
        out = _summarize(results)
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.producer_id,
            action="events.ingest",
            outcome="success",
            target_type="event_batch",
            request_id=request.state.request_id,
            details={
                "channel": "agent",
                "accepted": out.accepted,
                "duplicate": out.duplicate,
                "rejected": out.rejected,
            },
        )
    status = (
        207 if out.rejected and (out.accepted or out.duplicate) else (422 if out.rejected else 200)
    )
    return JSONResponse(out.model_dump(mode="json"), status_code=status)
