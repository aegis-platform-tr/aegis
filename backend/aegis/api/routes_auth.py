"""Authentication: development identities provisioned in the database (ADR-0003)."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from aegis import audit
from aegis.api.deps import get_principal
from aegis.api.errors import ApiError
from aegis.api.schemas import LoginIn, TokenOut, UserOut
from aegis.config import Settings, get_settings
from aegis.db import session_scope
from aegis.models import RevokedToken, User
from aegis.security import Principal, capabilities_for, issue_access_token, verify_password

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

LOGIN_FAILURE_LIMIT = 5
LOGIN_FAILURE_WINDOW_SECONDS = 300


class FailureTracker:
    """In-process login throttle keyed by username. Single-process only (documented M1
    limitation); a shared store is required once the API runs as several replicas."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def blocked(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._failures[key]
            while q and now - q[0] > LOGIN_FAILURE_WINDOW_SECONDS:
                q.popleft()
            return len(q) >= LOGIN_FAILURE_LIMIT

    def fail(self, key: str) -> None:
        with self._lock:
            self._failures[key].append(time.monotonic())

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._failures.clear()
            else:
                self._failures.pop(key, None)


failures = FailureTracker()


def user_out(username: str, tenant_id: str, roles: list[str]) -> UserOut:
    return UserOut(
        username=username,
        tenant_id=tenant_id,
        roles=roles,
        capabilities=sorted(c.value for c in capabilities_for(roles)),
    )


def _audit_login(rid: str, actor: str, outcome: str, tenant_id: str | None = None) -> None:
    with session_scope(tenant_id=tenant_id) as s:
        audit.record(
            s,
            tenant_id=tenant_id,
            actor=actor,
            action="auth.login",
            outcome=outcome,
            request_id=rid,
        )


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, settings: Settings = Depends(get_settings)) -> TokenOut:
    key = body.username.lower()
    rid: str = request.state.request_id
    if failures.blocked(key):
        _audit_login(rid, f"anonymous:{key}", "throttled")
        raise ApiError(429, "too_many_attempts", "Too many failed attempts; try again later")

    with session_scope() as s:
        user = s.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
        snapshot = (
            (
                user.id,
                user.username,
                user.tenant_id,
                list(user.roles),
                user.is_active,
                user.password_hash,
            )
            if user
            else None
        )
    ok = verify_password(snapshot[5] if snapshot else None, body.password)
    if not ok or snapshot is None or not snapshot[4]:
        failures.fail(key)
        _audit_login(rid, f"anonymous:{key}", "denied")
        raise ApiError(401, "invalid_credentials", "Invalid username or password")

    user_id, username, tenant_id, roles, _, _ = snapshot
    failures.reset(key)
    token, exp = issue_access_token(
        settings, user_id=user_id, username=username, tenant_id=tenant_id, roles=roles
    )
    _audit_login(rid, f"user:{user_id}", "success", tenant_id)
    return TokenOut(access_token=token, expires_at=exp, user=user_out(username, tenant_id, roles))


@router.get("/me", response_model=UserOut)
def me(principal: Principal = Depends(get_principal)) -> UserOut:
    return user_out(principal.username, principal.tenant_id, list(principal.roles))


@router.post("/logout", status_code=204)
def logout(request: Request, principal: Principal = Depends(get_principal)) -> None:
    with session_scope(tenant_id=principal.tenant_id) as s:
        s.execute(
            pg_insert(RevokedToken)
            .values(jti=principal.jti, expires_at=principal.expires_at)
            .on_conflict_do_nothing()
        )
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.subject,
            action="auth.logout",
            outcome="success",
            request_id=request.state.request_id,
        )
