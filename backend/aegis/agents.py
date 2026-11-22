"""Agent enrollment, credentials and heartbeats (ADR-0006).

Secrets are 256-bit random values. Only their SHA-256 digests are stored: for high-entropy
random tokens a fast hash is appropriate (no dictionary to attack), unlike user passwords.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from aegis.models import Agent, AgentCredential, EnrollmentToken

ENROLLMENT_PREFIX = "aegis_enr_"
CREDENTIAL_PREFIX = "aegis_agt_"
DEFAULT_ENROLLMENT_TTL = timedelta(hours=1)
MAX_ENROLLMENT_TTL = timedelta(hours=24)
CREDENTIAL_TTL = timedelta(days=30)
STALE_AFTER = timedelta(seconds=90)
MIN_SUPPORTED_AGENT_VERSION = (0, 1, 0)
ACCEPTED_SCHEMA_VERSIONS = ["1.0"]


def digest(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def parse_version(v: str) -> tuple[int, int, int] | None:
    try:
        parts = [int(p) for p in v.split("-", 1)[0].split(".")]
    except ValueError:
        return None
    if len(parts) != 3 or any(p < 0 for p in parts):
        return None
    return parts[0], parts[1], parts[2]


@dataclass(frozen=True)
class AgentPrincipal:
    agent_id: str
    tenant_id: str
    credential_hash: str
    expires_at: datetime

    @property
    def producer_id(self) -> str:
        return f"agent:{self.agent_id}"


class AgentAuthError(Exception):
    pass


class EnrollmentError(Exception):
    pass


def create_enrollment_token(
    session: Session, *, tenant_id: str, created_by: str, label: str, ttl: timedelta
) -> tuple[str, datetime]:
    ttl = min(ttl, MAX_ENROLLMENT_TTL)
    token = ENROLLMENT_PREFIX + secrets.token_urlsafe(32)
    expires = datetime.now(UTC) + ttl
    session.add(
        EnrollmentToken(
            token_hash=digest(token),
            tenant_id=tenant_id,
            created_by=created_by,
            label=label,
            expires_at=expires,
        )
    )
    return token, expires


def _issue_credential(session: Session, agent_id: str, tenant_id: str) -> tuple[str, datetime]:
    secret = CREDENTIAL_PREFIX + secrets.token_urlsafe(32)
    expires = datetime.now(UTC) + CREDENTIAL_TTL
    session.add(
        AgentCredential(
            credential_hash=digest(secret),
            agent_id=agent_id,
            tenant_id=tenant_id,
            expires_at=expires,
        )
    )
    return secret, expires


def enroll(
    session: Session, *, token: str, hostname: str, platform: str, agent_version: str
) -> tuple[Agent, str, datetime]:
    """Consume a single-use enrollment token atomically and create an agent identity."""
    if not token.startswith(ENROLLMENT_PREFIX):
        raise EnrollmentError("invalid enrollment token")
    agent_id = f"agt_{uuid.uuid4().hex}"
    consumed = session.execute(
        update(EnrollmentToken)
        .where(
            EnrollmentToken.token_hash == digest(token),
            EnrollmentToken.used_at.is_(None),
            EnrollmentToken.expires_at > datetime.now(UTC),
        )
        .values(used_at=datetime.now(UTC), used_by_agent=agent_id)
        .returning(EnrollmentToken.tenant_id)
    ).scalar_one_or_none()
    if consumed is None:
        raise EnrollmentError("enrollment token is invalid, expired or already used")
    from aegis.db import set_tenant

    set_tenant(session, consumed)
    agent = Agent(
        id=agent_id,
        tenant_id=consumed,
        hostname=hostname,
        platform=platform,
        agent_version=agent_version,
        status="active",
    )
    session.add(agent)
    session.flush()
    secret, expires = _issue_credential(session, agent_id, consumed)
    return agent, secret, expires


def authenticate(session: Session, credential: str) -> AgentPrincipal:
    if not credential.startswith(CREDENTIAL_PREFIX):
        raise AgentAuthError("invalid credential")
    row = session.execute(
        select(AgentCredential).where(AgentCredential.credential_hash == digest(credential))
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if row is None or row.revoked_at is not None or row.expires_at <= now:
        raise AgentAuthError("invalid credential")
    return AgentPrincipal(row.agent_id, row.tenant_id, row.credential_hash, row.expires_at)


def rotate(session: Session, principal: AgentPrincipal) -> tuple[str, datetime]:
    """Issue a new credential and revoke the one used for this request."""
    session.execute(
        update(AgentCredential)
        .where(AgentCredential.credential_hash == principal.credential_hash)
        .values(revoked_at=datetime.now(UTC))
    )
    return _issue_credential(session, principal.agent_id, principal.tenant_id)


def revoke(session: Session, *, agent: Agent, actor: str, reason: str) -> None:
    now = datetime.now(UTC)
    agent.status = "revoked"
    agent.revoked_at = now
    agent.revoked_by = actor
    agent.revoke_reason = reason
    session.execute(
        update(AgentCredential)
        .where(AgentCredential.agent_id == agent.id, AgentCredential.revoked_at.is_(None))
        .values(revoked_at=now)
    )


def record_heartbeat(
    session: Session, principal: AgentPrincipal, payload: dict[str, Any], agent_time: datetime
) -> Agent:
    agent = session.execute(select(Agent).where(Agent.id == principal.agent_id)).scalar_one()
    now = datetime.now(UTC)
    agent.last_seen_at = now
    agent.last_heartbeat = payload
    agent.clock_skew_ms = int((agent_time - now).total_seconds() * 1000)
    if payload.get("agent_version"):
        agent.agent_version = str(payload["agent_version"])
    return agent


def health_status(agent: Agent, now: datetime | None = None) -> str:
    """active | stale | never_seen | revoked | degraded (agent reported a problem)."""
    now = now or datetime.now(UTC)
    if agent.status == "revoked":
        return "revoked"
    if agent.last_seen_at is None:
        return "never_seen"
    if now - agent.last_seen_at > STALE_AFTER:
        return "stale"
    hb = agent.last_heartbeat or {}
    if hb.get("spool_full") or any(
        s.get("status") not in ("ok", None) for s in hb.get("sources", [])
    ):
        return "degraded"
    return "active"
