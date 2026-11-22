"""Request dependencies: authentication, capability checks, tenant-scoped sessions."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.api.errors import ApiError
from aegis.config import Settings, get_settings
from aegis.db import session_scope
from aegis.models import RevokedToken
from aegis.security import Capability, Principal, decode_access_token

_bearer = HTTPBearer(auto_error=False)


def get_principal(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    settings: Settings = Depends(get_settings),
) -> Principal:
    if creds is None or creds.scheme.lower() != "bearer":
        raise ApiError(401, "unauthenticated", "Authentication required")
    try:
        principal = decode_access_token(settings, creds.credentials)
    except jwt.PyJWTError as exc:
        raise ApiError(401, "invalid_token", "Invalid or expired token") from exc
    with session_scope() as session:
        revoked = session.execute(
            select(RevokedToken.jti).where(RevokedToken.jti == principal.jti)
        ).scalar_one_or_none()
    if revoked:
        raise ApiError(401, "invalid_token", "Invalid or expired token")
    request.state.principal = principal
    return principal


def require(capability: Capability) -> Callable[..., Principal]:
    def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.can(capability):
            raise ApiError(403, "forbidden", f"Missing capability {capability.value}")
        return principal

    return _dep


def tenant_session(principal: Principal = Depends(get_principal)) -> Iterator[Session]:
    """Session whose RLS scope is the authenticated tenant. Never taken from the request."""
    with session_scope(tenant_id=principal.tenant_id) as session:
        yield session
