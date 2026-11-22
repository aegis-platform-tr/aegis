"""Tool broker: model tool calls are untrusted proposals.

Each tool has a typed argument schema, a read/write class and a required capability. The broker
binds every call to the authenticated principal and tenant, enforces quotas and the tenant AI
policy, checks resource ownership, and records the decision. Write tools never change system
state directly: the only write tool creates a *response proposal* that still needs preview and
independent human approval (M5).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.models import AiTenantPolicy, DetectionAlert, Incident, SecurityEvent
from aegis.security import Capability, Principal

MAX_TOOL_CALLS_PER_REQUEST = 5


class GetIncidentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: str = Field(pattern=r"^inc_[0-9a-f]{32}$")


class GetEventArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(pattern=r"^evt_[0-9a-f]{32}$")


class ListAlertsArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit: int = Field(default=10, ge=1, le=20)


class ProposeBlockArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cidr: str = Field(max_length=64)
    minutes: int = Field(ge=5, le=1440)
    reason: str = Field(min_length=3, max_length=500)
    incident_id: str | None = Field(default=None, pattern=r"^inc_[0-9a-f]{32}$")


@dataclass
class ToolContext:
    session: Session
    principal: Principal
    policy: AiTenantPolicy
    request_capability: str
    tainted: bool  # untrusted input carried injection signals


@dataclass
class Tool:
    name: str
    access: Literal["read", "write"]
    capability: Capability
    schema: type[BaseModel]
    run: Callable[[ToolContext, Any], dict[str, Any]]


@dataclass
class ToolDecision:
    name: str
    decision: Literal["executed", "denied", "require_review", "invalid"]
    reason: str
    executed: bool = False
    result: dict[str, Any] | None = None
    audit: dict[str, Any] = field(default_factory=dict)

    def record(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "decision": self.decision,
            "reason": self.reason,
            "executed": self.executed,
        } | self.audit


def _get_incident(ctx: ToolContext, args: GetIncidentArgs) -> dict[str, Any]:
    inc = ctx.session.execute(
        select(Incident).where(
            Incident.tenant_id == ctx.principal.tenant_id, Incident.id == args.incident_id
        )
    ).scalar_one_or_none()
    if inc is None:
        raise LookupError("incident not found in tenant")
    return {
        "incident_id": inc.id,
        "title": inc.title,
        "status": inc.status,
        "severity": inc.severity,
        "correlation_key": inc.correlation_key,
    }


def _get_event(ctx: ToolContext, args: GetEventArgs) -> dict[str, Any]:
    ev = ctx.session.execute(
        select(SecurityEvent).where(
            SecurityEvent.tenant_id == ctx.principal.tenant_id, SecurityEvent.id == args.event_id
        )
    ).scalar_one_or_none()
    if ev is None:
        raise LookupError("event not found in tenant")
    return {
        "event_id": ev.id,
        "event_type": ev.event_type,
        "origin": ev.origin,
        "source_ip": str(ev.source_ip) if ev.source_ip else None,
    }


def _list_alerts(ctx: ToolContext, args: ListAlertsArgs) -> dict[str, Any]:
    rows = ctx.session.scalars(
        select(DetectionAlert)
        .where(DetectionAlert.tenant_id == ctx.principal.tenant_id)
        .order_by(DetectionAlert.evaluated_at.desc())
        .limit(args.limit)
    ).all()
    return {
        "alerts": [{"alert_id": a.id, "rule_id": a.rule_id, "severity": a.severity} for a in rows]
    }


def _propose_block(ctx: ToolContext, args: ProposeBlockArgs) -> dict[str, Any]:
    from aegis.responses import create_proposal_from_ai

    return create_proposal_from_ai(
        ctx.session, ctx.principal, args.cidr, args.minutes, args.reason, args.incident_id
    )


TOOLS: dict[str, Tool] = {
    t.name: t
    for t in (
        Tool("get_incident", "read", Capability.INCIDENTS_READ, GetIncidentArgs, _get_incident),
        Tool("get_event", "read", Capability.EVENTS_READ, GetEventArgs, _get_event),
        Tool("list_recent_alerts", "read", Capability.ALERTS_READ, ListAlertsArgs, _list_alerts),
        Tool(
            "propose_block", "write", Capability.RESPONSES_PROPOSE, ProposeBlockArgs, _propose_block
        ),
    )
}
WRITE_CAPABLE_REQUESTS = frozenset({"draft_response"})


def available_tools(ctx: ToolContext) -> list[str]:
    if not ctx.policy.allow_tools:
        return []
    return [t.name for t in TOOLS.values() if ctx.principal.can(t.capability)]


def broker(ctx: ToolContext, calls: list[tuple[str, dict[str, Any]]]) -> list[ToolDecision]:
    out: list[ToolDecision] = []
    for i, (name, raw_args) in enumerate(calls):
        if i >= MAX_TOOL_CALLS_PER_REQUEST:
            out.append(ToolDecision(name, "denied", "tool call quota exceeded"))
            continue
        tool = TOOLS.get(name)
        if tool is None:
            out.append(ToolDecision(name, "denied", "unknown tool"))
            continue
        if not ctx.policy.allow_tools:
            out.append(ToolDecision(name, "denied", "tenant policy disables tools"))
            continue
        if not ctx.principal.can(tool.capability):
            out.append(ToolDecision(name, "denied", f"principal lacks {tool.capability.value}"))
            continue
        if tool.access == "write":
            if ctx.request_capability not in WRITE_CAPABLE_REQUESTS:
                out.append(
                    ToolDecision(
                        name, "denied", "write tools are not available to this request type"
                    )
                )
                continue
            if not ctx.policy.allow_write_proposals:
                out.append(ToolDecision(name, "denied", "tenant policy disables write proposals"))
                continue
            if ctx.tainted:
                out.append(
                    ToolDecision(
                        name,
                        "require_review",
                        "untrusted input carried injection signals; write "
                        "proposal withheld for human review",
                    )
                )
                continue
        try:
            args = tool.schema.model_validate(raw_args)
        except ValidationError:
            out.append(ToolDecision(name, "invalid", "arguments failed schema validation"))
            continue
        try:
            result = tool.run(ctx, args)
        except (LookupError, ValueError) as exc:
            out.append(ToolDecision(name, "denied", str(exc)[:200]))
            continue
        decision: Literal["executed", "require_review"] = (
            "require_review" if tool.access == "write" else "executed"
        )
        out.append(
            ToolDecision(
                name,
                decision,
                "proposal created; requires preview and independent approval"
                if tool.access == "write"
                else "read-only tool executed",
                executed=True,
                result=result,
            )
        )
    return out
