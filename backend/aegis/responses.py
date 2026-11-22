"""Response transactions: proposal -> preview -> approval -> apply -> verify (-> rollback).

Only one typed action exists: a time-limited ``block_cidr`` on an explicitly managed resource.
There is no path from an API field, rule, playbook or model output to arbitrary command
execution. Live writes are disabled at the schema level (``live_writes_enabled`` is
constrained to false); the ``simulation`` adapter keeps an authoritative policy snapshot in the
database and never touches the host. ``nftables`` and ``windows_firewall`` adapters only
*render* the exact change for review (dry-run), with impact coverage reported as unknown, so
automatic application is refused for them.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.models import ManagedResource, ResponseApproval, ResponseExecution, ResponseProposal
from aegis.security import Principal

PROPOSAL_TTL = timedelta(hours=24)
APPROVAL_TTL = timedelta(minutes=30)
MIN_IPV4_PREFIX = 16
MIN_IPV6_PREFIX = 48
MAX_BLOCK_MINUTES = 1440
TERMINAL = frozenset(
    {"denied", "expired", "invalidated", "verified", "failed", "partial", "rolled_back"}
)


class ResponseError(Exception):
    """``persist=True`` means state changes made before the error (e.g. marking a proposal
    invalidated) must be committed even though the request fails."""

    def __init__(self, status: int, code: str, message: str, persist: bool = False) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.persist = status, code, message, persist


def _now() -> datetime:
    return datetime.now(UTC)


def validate_cidr(raw: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        net = ipaddress.ip_network(raw.strip(), strict=True)
    except ValueError as exc:
        raise ResponseError(
            422, "invalid_cidr", "Not a valid network (use canonical CIDR)"
        ) from exc
    min_prefix = MIN_IPV4_PREFIX if net.version == 4 else MIN_IPV6_PREFIX
    if net.prefixlen < min_prefix:
        raise ResponseError(
            422, "scope_too_broad", f"Blocks broader than /{min_prefix} are not allowed"
        )
    if net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified:
        raise ResponseError(422, "protected_range", "Loopback/link-local/multicast not allowed")
    return net


def _sha(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


# ---- Adapters -----------------------------------------------------------------------------


def render_change(resource: ManagedResource, rule: dict[str, Any]) -> dict[str, Any]:
    """Exact, reviewable change text for each adapter (rendered, never executed here)."""
    cidr, minutes, iface = rule["cidr"], rule["minutes"], resource.interface
    family = "ip6" if ":" in cidr else "ip"
    if resource.adapter == "nftables":
        return {
            "format": "nft",
            "text": (
                f"add element inet aegis blocklist_{'v6' if family == 'ip6' else 'v4'} "
                f"{{ {cidr} timeout {minutes}m }}  # iif {iface}"
            ),
        }
    if resource.adapter == "windows_firewall":
        return {
            "format": "powershell",
            "text": (
                f"New-NetFirewallRule -DisplayName 'AEGIS {rule['rule_id']}' -Direction Inbound "
                f"-Action Block -RemoteAddress {cidr} -InterfaceAlias '{iface}'  "
                f"# remove after {minutes} min"
            ),
        }
    return {"format": "simulation", "text": f"drop from {cidr} on {iface} for {minutes} min"}


def _covering(cidr: str, others: list[str]) -> list[str]:
    net = ipaddress.ip_network(cidr)
    hits = []
    for o in others:
        other = ipaddress.ip_network(o)
        if other.version == net.version and net.overlaps(other):
            hits.append(o)
    return hits


def _active_rules(snapshot: dict[str, Any], now: datetime) -> list[dict[str, Any]]:
    return [r for r in snapshot.get("rules", []) if datetime.fromisoformat(r["expires_at"]) > now]


# ---- Lifecycle ----------------------------------------------------------------------------


def get_resource(session: Session, tenant_id: str, resource_id: str) -> ManagedResource:
    res = session.execute(
        select(ManagedResource).where(
            ManagedResource.tenant_id == tenant_id, ManagedResource.id == resource_id
        )
    ).scalar_one_or_none()
    if res is None or not res.enabled:
        raise ResponseError(404, "not_found", "Managed resource not found or disabled")
    return res


def propose(
    session: Session,
    principal: Principal,
    *,
    resource_id: str,
    cidr: str,
    minutes: int,
    reason: str,
    evidence: dict[str, Any],
    author_kind: str = "human",
) -> ResponseProposal:
    if not 5 <= minutes <= MAX_BLOCK_MINUTES:
        raise ResponseError(422, "invalid_duration", f"minutes must be 5..{MAX_BLOCK_MINUTES}")
    net = validate_cidr(cidr)
    res = get_resource(session, principal.tenant_id, resource_id)
    rule_id = f"aegis-{uuid.uuid4().hex[:12]}"
    rule = {
        "rule_id": rule_id,
        "action": "drop",
        "cidr": str(net),
        "minutes": minutes,
        "interface": res.interface,
    }
    diff = {
        "add": [rule],
        "remove": [],
        "resource_id": res.id,
        "base_policy_revision": res.policy_revision,
    }
    proposal = ResponseProposal(
        id=f"rsp_{uuid.uuid4().hex}",
        tenant_id=principal.tenant_id,
        resource_id=res.id,
        action_type="block_cidr",
        payload={"cidr": str(net), "minutes": minutes},
        diff=diff,
        diff_sha256=_sha(diff),
        base_policy_revision=res.policy_revision,
        author=principal.subject,
        author_kind=author_kind,
        reason=reason,
        evidence=evidence,
        safeguards={
            "max_minutes": MAX_BLOCK_MINUTES,
            "protected_cidrs": res.protected_cidrs,
            "independent_approval": True,
            "approval_ttl_minutes": 30,
            "auto_expire": True,
        },
        status="proposed",
        expires_at=_now() + PROPOSAL_TTL,
    )
    session.add(proposal)
    session.flush()
    return proposal


def load(
    session: Session, tenant_id: str, proposal_id: str, lock: bool = False
) -> ResponseProposal:
    q = select(ResponseProposal).where(
        ResponseProposal.tenant_id == tenant_id, ResponseProposal.id == proposal_id
    )
    if lock:
        q = q.with_for_update()
    p = session.execute(q).scalar_one_or_none()
    if p is None:
        raise ResponseError(404, "not_found", "Proposal not found")
    return p


def _expire_if_due(p: ResponseProposal) -> None:
    if p.status not in TERMINAL and p.status not in ("applied",) and p.expires_at <= _now():
        p.status, p.status_reason = "expired", "proposal expired before execution"


def preview(session: Session, principal: Principal, proposal_id: str) -> ResponseProposal:
    p = load(session, principal.tenant_id, proposal_id, lock=True)
    _expire_if_due(p)
    if p.status not in ("proposed", "previewed", "approval_pending"):
        raise ResponseError(409, "invalid_state", f"Cannot preview a proposal in {p.status}")
    res = get_resource(session, principal.tenant_id, p.resource_id)
    rule = p.diff["add"][0]
    now = _now()
    before = _active_rules(res.policy_snapshot, now)
    protected_hits = _covering(rule["cidr"], res.protected_cidrs)
    conflicts = [r["rule_id"] for r in before if _covering(rule["cidr"], [r["cidr"]])]
    net = ipaddress.ip_network(rule["cidr"])
    coverage = "known" if res.adapter == "simulation" else "unknown"
    p.preview = {
        "adapter": res.adapter,
        "interface": res.interface,
        "coverage": coverage,
        "policy_revision": res.policy_revision,
        "before": before,
        "after": [*before, rule | {"expires_in_minutes": rule["minutes"]}],
        "affected_cidrs": [rule["cidr"]],
        "addresses_affected": net.num_addresses,
        "conflicting_rules": conflicts,
        "protected_path_conflicts": protected_hits,
        "rendered_change": render_change(res, rule),
        "automatic_apply_allowed": coverage == "known" and not protected_hits,
        "host_state": "unchanged (preview only)",
        "previewed_at": now.isoformat(),
        "diff_sha256": p.diff_sha256,
    }
    if p.base_policy_revision != res.policy_revision:
        p.status, p.status_reason = "invalidated", "authoritative policy changed since proposal"
    elif protected_hits:
        p.status, p.status_reason = "approval_pending", "blocked: overlaps protected paths"
    else:
        p.status, p.status_reason = "approval_pending", None
    p.version += 1
    p.updated_at = now
    return p


def decide(
    session: Session, principal: Principal, proposal_id: str, approve: bool, reason: str
) -> ResponseProposal:
    p = load(session, principal.tenant_id, proposal_id, lock=True)
    _expire_if_due(p)
    if p.status != "approval_pending":
        raise ResponseError(
            409, "invalid_state", f"Proposal must be previewed and pending approval (is {p.status})"
        )
    if p.author == principal.subject:
        raise ResponseError(
            403,
            "self_approval",
            "The author cannot approve or deny their own "
            "proposal (including AI-drafted proposals they requested)",
        )
    res = get_resource(session, principal.tenant_id, p.resource_id)
    preview_data = p.preview or {}
    if approve:
        if preview_data.get("protected_path_conflicts"):
            raise ResponseError(409, "protected_conflict", "Change overlaps protected paths")
        if not preview_data.get("automatic_apply_allowed"):
            raise ResponseError(
                409,
                "unknown_impact",
                "Adapter cannot determine impact; automatic apply is disallowed",
            )
        if res.policy_revision != p.base_policy_revision:
            p.status, p.status_reason = "invalidated", "authoritative policy changed"
            raise ResponseError(409, "policy_changed", "Policy changed since preview", persist=True)
    session.add(
        ResponseApproval(
            id=f"apr_{uuid.uuid4().hex}",
            tenant_id=principal.tenant_id,
            proposal_id=p.id,
            approver=principal.subject,
            decision="approved" if approve else "denied",
            diff_sha256=p.diff_sha256,
            base_policy_revision=p.base_policy_revision,
            reason=reason,
            expires_at=_now() + APPROVAL_TTL,
        )
    )
    p.status = "approved" if approve else "denied"
    p.status_reason = reason
    p.version += 1
    p.updated_at = _now()
    return p


@dataclass
class ExecResult:
    proposal: ResponseProposal
    execution: ResponseExecution
    replayed: bool


def execute(
    session: Session, principal: Principal, proposal_id: str, idempotency_key: str
) -> ExecResult:
    existing = session.execute(
        select(ResponseExecution).where(
            ResponseExecution.tenant_id == principal.tenant_id,
            ResponseExecution.idempotency_key == idempotency_key,
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.proposal_id != proposal_id or existing.kind != "apply":
            raise ResponseError(409, "idempotency_key_reused", "Key already used for another call")
        return ExecResult(load(session, principal.tenant_id, proposal_id), existing, True)

    p = load(session, principal.tenant_id, proposal_id, lock=True)
    # Per-target operation lock: the resource row is locked for the whole transaction.
    res = session.execute(
        select(ManagedResource)
        .where(
            ManagedResource.tenant_id == principal.tenant_id, ManagedResource.id == p.resource_id
        )
        .with_for_update()
    ).scalar_one()
    _expire_if_due(p)
    if p.status in ("applied", "verified", "applying"):
        raise ResponseError(409, "already_executed", f"Proposal already {p.status}")
    if p.status != "approved":
        raise ResponseError(409, "not_approved", f"Proposal is {p.status}, not approved")
    approval = session.execute(
        select(ResponseApproval)
        .where(ResponseApproval.proposal_id == p.id, ResponseApproval.decision == "approved")
        .order_by(ResponseApproval.created_at.desc())
        .limit(1)
    ).scalar_one()
    checks = {
        "approval_unexpired": approval.expires_at > _now(),
        "diff_unchanged": approval.diff_sha256 == p.diff_sha256 == _sha(p.diff),
        "policy_unchanged": res.policy_revision
        == p.base_policy_revision
        == approval.base_policy_revision,
        "tenant_scope": res.tenant_id == p.tenant_id == principal.tenant_id,
        "adapter_supports_apply": res.adapter == "simulation",
        "no_protected_conflict": not _covering(p.diff["add"][0]["cidr"], res.protected_cidrs),
    }
    if not all(checks.values()):
        failed = [k for k, v in checks.items() if not v]
        p.status = "expired" if failed == ["approval_unexpired"] else "invalidated"
        p.status_reason = "execution refused: " + ", ".join(failed)
        p.version += 1
        raise ResponseError(409, "execution_refused", p.status_reason, persist=True)

    pre = json.loads(json.dumps(res.policy_snapshot))
    ex = ResponseExecution(
        id=f"rex_{uuid.uuid4().hex}",
        tenant_id=principal.tenant_id,
        proposal_id=p.id,
        idempotency_key=idempotency_key,
        kind="apply",
        actor=principal.subject,
        status="applying",
        pre_snapshot=pre,
    )
    session.add(ex)
    p.status = "applying"
    session.flush()
    _simulate_apply(res, p, ex, pre)
    p.version += 1
    p.updated_at = _now()
    ex.finished_at = _now()
    return ExecResult(p, ex, False)


def _simulate_apply(
    res: ManagedResource, p: ResponseProposal, ex: ResponseExecution, pre: dict[str, Any]
) -> None:
    rule = p.diff["add"][0]
    now = _now()
    if res.test_fail_mode == "apply_error":
        p.status, p.status_reason = "failed", "adapter reported apply error; state unchanged"
        ex.status, ex.error, ex.post_snapshot = "failed", "simulated apply error", pre
        return
    applied = rule | {
        "expires_at": (now + timedelta(minutes=rule["minutes"])).isoformat(),
        "proposal_id": p.id,
    }
    post = {"rules": [*_active_rules(pre, now), applied]}
    res.policy_snapshot = post
    res.policy_revision += 1
    if res.test_fail_mode == "unknown_result":
        # Result unknown: read back actual state before deciding anything.
        ex.status, p.status = "partial", "partial"
        ex.verification = {
            "read_back": "rule present" if applied in post["rules"] else "absent",
            "health_check": "not completed (simulated timeout)",
        }
        p.status_reason = (
            "apply result unknown; state read back shows rule present; health "
            "not verified. Human recovery: roll back or re-verify."
        )
        ex.post_snapshot = post
        return
    verification = _verify(res, applied)
    if res.test_fail_mode == "verify_error":
        verification["management_path_reachable"] = False
    ex.verification = verification
    if all(v is True for k, v in verification.items() if k.endswith(("_reachable", "_present"))):
        ex.status, p.status, ex.post_snapshot = "verified", "verified", post
        return
    # Verification failed: revert through the tested recovery path (restore pre-snapshot).
    res.policy_snapshot = pre
    res.policy_revision += 1
    ex.status, p.status = "rolled_back", "rolled_back"
    ex.post_snapshot = pre
    p.status_reason = "post-apply verification failed; automatically restored previous policy"


def _verify(res: ManagedResource, applied: dict[str, Any]) -> dict[str, Any]:
    rules = res.policy_snapshot.get("rules", [])
    protected_ok = not any(_covering(r["cidr"], res.protected_cidrs) for r in rules)
    return {
        "rule_present": applied in rules,
        "management_path_reachable": protected_ok,
        "policy_revision": res.policy_revision,
    }


def rollback(
    session: Session, principal: Principal, proposal_id: str, idempotency_key: str, reason: str
) -> ExecResult:
    existing = session.execute(
        select(ResponseExecution).where(
            ResponseExecution.tenant_id == principal.tenant_id,
            ResponseExecution.idempotency_key == idempotency_key,
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.proposal_id != proposal_id or existing.kind != "rollback":
            raise ResponseError(409, "idempotency_key_reused", "Key already used for another call")
        return ExecResult(load(session, principal.tenant_id, proposal_id), existing, True)
    p = load(session, principal.tenant_id, proposal_id, lock=True)
    if p.status not in ("verified", "partial"):
        raise ResponseError(409, "invalid_state", f"Nothing to roll back in state {p.status}")
    res = session.execute(
        select(ManagedResource).where(ManagedResource.id == p.resource_id).with_for_update()
    ).scalar_one()
    pre = json.loads(json.dumps(res.policy_snapshot))
    post = {"rules": [r for r in pre.get("rules", []) if r.get("proposal_id") != p.id]}
    res.policy_snapshot = post
    res.policy_revision += 1
    ex = ResponseExecution(
        id=f"rex_{uuid.uuid4().hex}",
        tenant_id=principal.tenant_id,
        proposal_id=p.id,
        idempotency_key=idempotency_key,
        kind="rollback",
        actor=principal.subject,
        status="rolled_back",
        pre_snapshot=pre,
        post_snapshot=post,
        finished_at=_now(),
        verification={"rule_absent": all(r.get("proposal_id") != p.id for r in post["rules"])},
    )
    session.add(ex)
    p.status, p.status_reason = "rolled_back", reason
    p.version += 1
    p.updated_at = _now()
    return ExecResult(p, ex, False)


def reconcile(session: Session, tenant_id: str, resource_id: str) -> dict[str, Any]:
    """Read authoritative state and drop expired rules (time-limited blocks)."""
    res = session.execute(
        select(ManagedResource)
        .where(ManagedResource.tenant_id == tenant_id, ManagedResource.id == resource_id)
        .with_for_update()
    ).scalar_one_or_none()
    if res is None:
        raise ResponseError(404, "not_found", "Managed resource not found")
    now = _now()
    rules = res.policy_snapshot.get("rules", [])
    active = _active_rules(res.policy_snapshot, now)
    removed = [r["rule_id"] for r in rules if r not in active]
    if removed:
        res.policy_snapshot = {"rules": active}
        res.policy_revision += 1
    return {
        "resource_id": res.id,
        "policy_revision": res.policy_revision,
        "active_rules": active,
        "expired_removed": removed,
    }


def create_proposal_from_ai(
    session: Session,
    principal: Principal,
    cidr: str,
    minutes: int,
    reason: str,
    incident_id: str | None,
) -> dict[str, Any]:
    """Used by the AI tool broker. Creates a *proposal only*; the requesting user becomes the
    author, so they cannot approve it themselves."""
    res = session.execute(
        select(ManagedResource)
        .where(
            ManagedResource.tenant_id == principal.tenant_id,
            ManagedResource.enabled.is_(True),
            ManagedResource.adapter == "simulation",
        )
        .order_by(ManagedResource.created_at)
        .limit(1)
    ).scalar_one_or_none()
    if res is None:
        raise LookupError("no enabled simulation resource for this tenant")
    try:
        p = propose(
            session,
            principal,
            resource_id=res.id,
            cidr=cidr,
            minutes=minutes,
            reason=f"[AI-drafted] {reason}",
            evidence={"incident_id": incident_id},
            author_kind="ai",
        )
    except ResponseError as exc:
        raise ValueError(exc.message) from exc
    return {"proposal_id": p.id, "status": p.status, "requires": "preview + independent approval"}
