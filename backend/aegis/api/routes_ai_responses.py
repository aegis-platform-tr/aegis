"""AI gateway and response-transaction endpoints."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from aegis import audit
from aegis import responses as rsp
from aegis.ai.gateway import AiRequestIn, GatewayError, get_policy, handle
from aegis.api.deps import require, tenant_session
from aegis.api.errors import ApiError
from aegis.db import session_scope
from aegis.models import (
    AiRequest,
    ManagedResource,
    ResponseApproval,
    ResponseExecution,
    ResponseProposal,
)
from aegis.security import Capability, Principal

router = APIRouter(prefix="/api/v1", tags=["ai", "responses"])
IdemKey = Annotated[
    str, Header(alias="Idempotency-Key", min_length=8, max_length=80, pattern=r"^[A-Za-z0-9_\-]+$")
]


# ---- AI gateway ---------------------------------------------------------------------------


class AiPolicyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["mock", "cloud_disabled", "none"]
    allow_tools: bool
    allow_write_proposals: bool
    share_principals: bool
    max_requests_per_day: int = Field(ge=0, le=100000)
    reason: str = Field(min_length=3, max_length=500)


def _policy_view(p: Any) -> dict[str, Any]:
    return {
        "revision": p.revision,
        "provider": p.provider,
        "allow_tools": p.allow_tools,
        "allow_write_proposals": p.allow_write_proposals,
        "share_principals": p.share_principals,
        "max_requests_per_day": p.max_requests_per_day,
        "updated_by": p.updated_by,
        "updated_at": p.updated_at,
    }


@router.post("/ai/requests")
def ai_request(
    body: AiRequestIn,
    request: Request,
    principal: Principal = Depends(require(Capability.AI_USE)),
) -> dict[str, Any]:
    with session_scope(tenant_id=principal.tenant_id) as s:
        try:
            out = handle(s, principal, body)
        except GatewayError as exc:
            raise ApiError(exc.status, exc.code, exc.message) from exc
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.subject,
            action="ai.request",
            outcome="success",
            target_type="ai_request",
            target_id=out.request_id,
            request_id=request.state.request_id,
            details={
                "capability": body.capability,
                "decision": out.decision,
                "status": out.status,
                "provider_called": out.provider_called,
                "tools": [t["name"] + ":" + t["decision"] for t in out.tool_calls],
            },
        )
        return out.as_dict()


@router.get("/ai/requests")
def ai_requests(
    principal: Principal = Depends(require(Capability.AI_AUDIT)),
    s: Session = Depends(tenant_session),
) -> list[dict[str, Any]]:
    rows = s.scalars(
        select(AiRequest)
        .where(AiRequest.tenant_id == principal.tenant_id)
        .order_by(desc(AiRequest.created_at))
        .limit(200)
    ).all()
    return [
        {
            "request_id": r.id,
            "actor": r.actor,
            "capability": r.capability,
            "policy_version": r.policy_version,
            "decision": r.decision,
            "status": r.status,
            "input_checks": r.input_checks,
            "output_checks": r.output_checks,
            "provider": r.provider,
            "model": r.model,
            "provider_called": r.provider_called,
            "tool_calls": r.tool_calls,
            "latency_ms": r.latency_ms,
            "cost_units": r.cost_units,
            "prompt_sha256": r.prompt_sha256,
            "prompt_chars": r.prompt_chars,
            "evidence_ids": r.evidence_ids,
            "error": r.error,
            "created_at": r.created_at,
        }
        for r in rows
    ]


@router.get("/ai/policy")
def ai_policy(principal: Principal = Depends(require(Capability.AI_USE))) -> dict[str, Any]:
    with session_scope(tenant_id=principal.tenant_id) as s:
        return _policy_view(get_policy(s, principal.tenant_id))


@router.put("/ai/policy")
def set_ai_policy(
    body: AiPolicyIn,
    request: Request,
    principal: Principal = Depends(require(Capability.AI_POLICY)),
) -> dict[str, Any]:
    with session_scope(tenant_id=principal.tenant_id) as s:
        p = get_policy(s, principal.tenant_id)
        before = _policy_view(p)
        for k in (
            "provider",
            "allow_tools",
            "allow_write_proposals",
            "share_principals",
            "max_requests_per_day",
        ):
            setattr(p, k, getattr(body, k))
        p.revision += 1
        p.updated_by = principal.subject
        s.flush()
        after = _policy_view(p)
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.subject,
            action="ai.policy.update",
            outcome="success",
            target_type="ai_policy",
            request_id=request.state.request_id,
            details={
                "reason": body.reason,
                "revision": p.revision,
                "changed": {
                    k: after[k]
                    for k in after
                    if k not in ("updated_at", "updated_by", "revision") and before[k] != after[k]
                },
            },
        )
        return after


# ---- Managed resources ---------------------------------------------------------------------


class ResourceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9 ._\-]+$")
    adapter: Literal["simulation", "nftables", "windows_firewall"]
    interface: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9 ._\-]+$")
    protected_cidrs: list[str] = Field(min_length=1, max_length=50)


def _resource_view(r: ManagedResource) -> dict[str, Any]:
    return {
        "resource_id": r.id,
        "name": r.name,
        "adapter": r.adapter,
        "interface": r.interface,
        "protected_cidrs": r.protected_cidrs,
        "enabled": r.enabled,
        "live_writes_enabled": r.live_writes_enabled,
        "mode": "simulation (host untouched)"
        if r.adapter == "simulation"
        else "dry-run render only; live apply not supported",
        "policy_revision": r.policy_revision,
        "policy_snapshot": r.policy_snapshot,
        "created_at": r.created_at,
    }


@router.get("/response/resources")
def list_resources(
    principal: Principal = Depends(require(Capability.RESPONSES_READ)),
    s: Session = Depends(tenant_session),
) -> list[dict[str, Any]]:
    rows = s.scalars(
        select(ManagedResource)
        .where(ManagedResource.tenant_id == principal.tenant_id)
        .order_by(ManagedResource.name)
    ).all()
    return [_resource_view(r) for r in rows]


@router.post("/response/resources", status_code=201)
def create_resource(
    body: ResourceIn,
    request: Request,
    principal: Principal = Depends(require(Capability.RESOURCES_MANAGE)),
) -> dict[str, Any]:
    import ipaddress

    try:
        protected = [str(ipaddress.ip_network(c, strict=True)) for c in body.protected_cidrs]
    except ValueError as exc:
        raise ApiError(422, "invalid_cidr", "protected_cidrs must be canonical CIDRs") from exc
    with session_scope(tenant_id=principal.tenant_id) as s:
        r = ManagedResource(
            id=f"res_{uuid.uuid4().hex}",
            tenant_id=principal.tenant_id,
            name=body.name,
            adapter=body.adapter,
            interface=body.interface,
            protected_cidrs=protected,
            enabled=True,
            live_writes_enabled=False,
            policy_revision=1,
            policy_snapshot={"rules": []},
            created_by=principal.subject,
        )
        s.add(r)
        s.flush()
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.subject,
            action="resource.create",
            outcome="success",
            target_type="resource",
            target_id=r.id,
            request_id=request.state.request_id,
            details={"adapter": body.adapter, "protected_cidrs": protected},
        )
        s.refresh(r)
        return _resource_view(r)


@router.post("/response/resources/{resource_id}/reconcile")
def reconcile_resource(
    resource_id: str,
    request: Request,
    principal: Principal = Depends(require(Capability.RESPONSES_EXECUTE)),
) -> dict[str, Any]:
    return _run(
        principal,
        request,
        "resource.reconcile",
        resource_id,
        lambda s: rsp.reconcile(s, principal.tenant_id, resource_id),
    )


# ---- Proposals -----------------------------------------------------------------------------


class ProposeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    resource_id: str = Field(max_length=40)
    cidr: str = Field(max_length=64)
    minutes: int = Field(ge=5, le=rsp.MAX_BLOCK_MINUTES)
    reason: str = Field(min_length=3, max_length=1000)
    incident_id: str | None = Field(default=None, pattern=r"^inc_[0-9a-f]{32}$")


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=3, max_length=1000)


def proposal_view(s: Session, p: ResponseProposal) -> dict[str, Any]:
    approvals = s.scalars(
        select(ResponseApproval)
        .where(ResponseApproval.proposal_id == p.id)
        .order_by(ResponseApproval.created_at)
    ).all()
    execs = s.scalars(
        select(ResponseExecution)
        .where(ResponseExecution.proposal_id == p.id)
        .order_by(ResponseExecution.started_at)
    ).all()
    return {
        "proposal_id": p.id,
        "resource_id": p.resource_id,
        "action_type": p.action_type,
        "payload": p.payload,
        "diff": p.diff,
        "diff_sha256": p.diff_sha256,
        "base_policy_revision": p.base_policy_revision,
        "author": p.author,
        "author_kind": p.author_kind,
        "reason": p.reason,
        "evidence": p.evidence,
        "safeguards": p.safeguards,
        "status": p.status,
        "status_reason": p.status_reason,
        "preview": p.preview,
        "expires_at": p.expires_at,
        "version": p.version,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
        "approvals": [
            {
                "approver": a.approver,
                "decision": a.decision,
                "reason": a.reason,
                "expires_at": a.expires_at,
                "at": a.created_at,
            }
            for a in approvals
        ],
        "executions": [
            {
                "execution_id": e.id,
                "kind": e.kind,
                "status": e.status,
                "actor": e.actor,
                "verification": e.verification,
                "error": e.error,
                "pre_snapshot": e.pre_snapshot,
                "post_snapshot": e.post_snapshot,
                "started_at": e.started_at,
                "finished_at": e.finished_at,
            }
            for e in execs
        ],
    }


def _run[T](
    principal: Principal, request: Request, action: str, target: str, fn: Callable[[Session], T]
) -> T:
    """Run a response operation; audit success and failure; persist refusals that changed
    state (e.g. invalidation) while still returning an error to the caller."""
    failure: rsp.ResponseError | None = None
    with session_scope(tenant_id=principal.tenant_id) as s:
        try:
            result = fn(s)
        except rsp.ResponseError as exc:
            if not exc.persist:
                raise ApiError(exc.status, exc.code, exc.message) from exc
            failure = exc
        if failure is None:  # failures are audited by _audit_failure_wrapper
            audit.record(
                s,
                tenant_id=principal.tenant_id,
                actor=principal.subject,
                action=action,
                outcome="success",
                target_type="proposal",
                target_id=target,
                request_id=request.state.request_id,
            )
    if failure is not None:
        raise ApiError(failure.status, failure.code, failure.message)
    return result


def _audit_failure_wrapper[T](
    principal: Principal, request: Request, action: str, target: str, fn: Callable[[Session], T]
) -> T:
    try:
        return _run(principal, request, action, target, fn)
    except ApiError as exc:
        with session_scope(tenant_id=principal.tenant_id) as s:
            audit.record(
                s,
                tenant_id=principal.tenant_id,
                actor=principal.subject,
                action=action,
                outcome="refused",
                target_type="proposal",
                target_id=target,
                request_id=request.state.request_id,
                details={"error": exc.code},
            )
        raise


@router.get("/responses")
def list_proposals(
    principal: Principal = Depends(require(Capability.RESPONSES_READ)),
    s: Session = Depends(tenant_session),
) -> list[dict[str, Any]]:
    rows = s.scalars(
        select(ResponseProposal)
        .where(ResponseProposal.tenant_id == principal.tenant_id)
        .order_by(desc(ResponseProposal.created_at))
        .limit(200)
    ).all()
    return [proposal_view(s, p) for p in rows]


@router.get("/responses/{proposal_id}")
def get_proposal(
    proposal_id: str,
    principal: Principal = Depends(require(Capability.RESPONSES_READ)),
    s: Session = Depends(tenant_session),
) -> dict[str, Any]:
    try:
        return proposal_view(s, rsp.load(s, principal.tenant_id, proposal_id))
    except rsp.ResponseError as exc:
        raise ApiError(exc.status, exc.code, exc.message) from exc


@router.post("/responses", status_code=201)
def create_proposal(
    body: ProposeIn,
    request: Request,
    principal: Principal = Depends(require(Capability.RESPONSES_PROPOSE)),
) -> dict[str, Any]:
    def op(s: Session) -> dict[str, Any]:
        p = rsp.propose(
            s,
            principal,
            resource_id=body.resource_id,
            cidr=body.cidr,
            minutes=body.minutes,
            reason=body.reason,
            evidence={"incident_id": body.incident_id},
        )
        return proposal_view(s, p)

    return _audit_failure_wrapper(principal, request, "response.propose", body.resource_id, op)


@router.post("/responses/{proposal_id}/preview")
def preview(
    proposal_id: str,
    request: Request,
    principal: Principal = Depends(require(Capability.RESPONSES_PROPOSE)),
) -> dict[str, Any]:
    return _audit_failure_wrapper(
        principal,
        request,
        "response.preview",
        proposal_id,
        lambda s: proposal_view(s, rsp.preview(s, principal, proposal_id)),
    )


@router.post("/responses/{proposal_id}/approve")
def approve(
    proposal_id: str,
    body: DecisionIn,
    request: Request,
    principal: Principal = Depends(require(Capability.RESPONSES_APPROVE)),
) -> dict[str, Any]:
    return _audit_failure_wrapper(
        principal,
        request,
        "response.approve",
        proposal_id,
        lambda s: proposal_view(s, rsp.decide(s, principal, proposal_id, True, body.reason)),
    )


@router.post("/responses/{proposal_id}/deny")
def deny(
    proposal_id: str,
    body: DecisionIn,
    request: Request,
    principal: Principal = Depends(require(Capability.RESPONSES_APPROVE)),
) -> dict[str, Any]:
    return _audit_failure_wrapper(
        principal,
        request,
        "response.deny",
        proposal_id,
        lambda s: proposal_view(s, rsp.decide(s, principal, proposal_id, False, body.reason)),
    )


@router.post("/responses/{proposal_id}/execute")
def execute(
    proposal_id: str,
    request: Request,
    idempotency_key: IdemKey,
    principal: Principal = Depends(require(Capability.RESPONSES_EXECUTE)),
) -> dict[str, Any]:
    def op(s: Session) -> dict[str, Any]:
        r = rsp.execute(s, principal, proposal_id, idempotency_key)
        return proposal_view(s, r.proposal) | {"replayed": r.replayed}

    return _audit_failure_wrapper(principal, request, "response.execute", proposal_id, op)


@router.post("/responses/{proposal_id}/rollback")
def rollback(
    proposal_id: str,
    body: DecisionIn,
    request: Request,
    idempotency_key: IdemKey,
    principal: Principal = Depends(require(Capability.RESPONSES_EXECUTE)),
) -> dict[str, Any]:
    def op(s: Session) -> dict[str, Any]:
        r = rsp.rollback(s, principal, proposal_id, idempotency_key, body.reason)
        return proposal_view(s, r.proposal) | {"replayed": r.replayed}

    return _audit_failure_wrapper(principal, request, "response.rollback", proposal_id, op)
