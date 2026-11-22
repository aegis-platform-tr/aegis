"""Append-only audit records. The runtime DB role has no UPDATE/DELETE on audit_logs."""

from __future__ import annotations

from typing import Any

from sqlalchemy import insert
from sqlalchemy.orm import Session

from aegis.models import AuditLog


def record(
    session: Session,
    *,
    tenant_id: str | None,
    actor: str,
    action: str,
    outcome: str,
    target_type: str | None = None,
    target_id: str | None = None,
    request_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    # Core INSERT without RETURNING: rows with no tenant (pre-auth events) are insertable but
    # intentionally not readable through RLS, and RETURNING would require read access.
    session.connection().execute(
        insert(AuditLog).values(
            tenant_id=tenant_id,
            actor=actor,
            action=action,
            outcome=outcome,
            target_type=target_type,
            target_id=target_id,
            request_id=request_id,
            details=details or {},
        )
    )
