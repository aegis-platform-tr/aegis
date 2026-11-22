"""Identity, credentials and capability checks (ADR-0003)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from aegis.config import Settings

_hasher = PasswordHasher()  # Argon2id with library defaults
JWT_ALGORITHM = "HS256"
# Constant hash used to equalize timing when the username does not exist.
_DUMMY_HASH = _hasher.hash("aegis-timing-equalizer")


class Capability(StrEnum):
    EVENTS_INGEST = "events:ingest"
    EVENTS_READ = "events:read"
    ALERTS_READ = "alerts:read"
    RULES_READ = "rules:read"
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_UPDATE = "incidents:update"
    AUDIT_READ = "audit:read"
    FIXTURES_IMPORT = "fixtures:import"
    AGENTS_READ = "agents:read"
    AGENTS_MANAGE = "agents:manage"
    RULES_WRITE = "rules:write"
    SUPPRESSIONS_MANAGE = "suppressions:manage"
    NETWORK_READ = "network:read"
    AI_USE = "ai:use"
    AI_AUDIT = "ai:audit"
    RESPONSES_READ = "responses:read"
    RESPONSES_PROPOSE = "responses:propose"
    RESPONSES_APPROVE = "responses:approve"
    RESPONSES_EXECUTE = "responses:execute"


_READ = {
    Capability.EVENTS_READ,
    Capability.ALERTS_READ,
    Capability.RULES_READ,
    Capability.INCIDENTS_READ,
    Capability.AGENTS_READ,
    Capability.NETWORK_READ,
}

# Capability matrix (docs/security/capability-matrix.md). Server-side source of truth.
ROLE_CAPABILITIES: dict[str, frozenset[Capability]] = {
    "viewer": frozenset(_READ),
    "analyst": frozenset(
        _READ
        | {
            Capability.INCIDENTS_UPDATE,
            Capability.EVENTS_INGEST,
            Capability.FIXTURES_IMPORT,
            Capability.SUPPRESSIONS_MANAGE,
            Capability.AI_USE,
            Capability.RESPONSES_READ,
        }
    ),
    "detection_maintainer": frozenset(
        _READ | {Capability.RULES_WRITE, Capability.SUPPRESSIONS_MANAGE, Capability.AI_USE}
    ),
    "response_proposer": frozenset(
        _READ | {Capability.RESPONSES_READ, Capability.RESPONSES_PROPOSE, Capability.AI_USE}
    ),
    "response_approver": frozenset(
        _READ
        | {Capability.RESPONSES_READ, Capability.RESPONSES_APPROVE, Capability.RESPONSES_EXECUTE}
    ),
    "tenant_admin": frozenset(
        _READ
        | {
            Capability.AUDIT_READ,
            Capability.FIXTURES_IMPORT,
            Capability.AGENTS_MANAGE,
            Capability.RULES_WRITE,
            Capability.SUPPRESSIONS_MANAGE,
            Capability.AI_USE,
            Capability.AI_AUDIT,
            Capability.RESPONSES_READ,
        }
    ),
    "auditor": frozenset(
        {
            Capability.AUDIT_READ,
            Capability.INCIDENTS_READ,
            Capability.AI_AUDIT,
            Capability.RESPONSES_READ,
        }
    ),
}


def capabilities_for(roles: tuple[str, ...] | list[str]) -> frozenset[Capability]:
    caps: set[Capability] = set()
    for role in roles:
        caps |= ROLE_CAPABILITIES.get(role, frozenset())
    return frozenset(caps)


@dataclass(frozen=True)
class Principal:
    subject: str  # "user:<uuid>"
    username: str
    tenant_id: str
    roles: tuple[str, ...]
    jti: str
    expires_at: datetime

    @property
    def capabilities(self) -> frozenset[Capability]:
        return capabilities_for(self.roles)

    def can(self, capability: Capability) -> bool:
        return capability in self.capabilities


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def issue_access_token(
    settings: Settings, *, user_id: uuid.UUID, username: str, tenant_id: str, roles: list[str]
) -> tuple[str, datetime]:
    now = datetime.now(UTC)
    exp = now + timedelta(seconds=settings.access_token_ttl_seconds)
    claims: dict[str, Any] = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": f"user:{user_id}",
        "usr": username,
        "tid": tenant_id,
        "roles": roles,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(claims, settings.jwt_secret.get_secret_value(), algorithm=JWT_ALGORITHM)
    return token, exp


def decode_access_token(settings: Settings, token: str) -> Principal:
    """Raises jwt.PyJWTError on any invalid token. Only HS256 is accepted (no 'none')."""
    claims = jwt.decode(
        token,
        settings.jwt_secret.get_secret_value(),
        algorithms=[JWT_ALGORITHM],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
        options={"require": ["exp", "iat", "nbf", "sub", "tid", "jti", "aud", "iss"]},
    )
    roles = claims.get("roles")
    if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
        raise jwt.InvalidTokenError("invalid roles claim")
    return Principal(
        subject=str(claims["sub"]),
        username=str(claims.get("usr", "")),
        tenant_id=str(claims["tid"]),
        roles=tuple(roles),
        jti=str(claims["jti"]),
        expires_at=datetime.fromtimestamp(int(claims["exp"]), tz=UTC),
    )
