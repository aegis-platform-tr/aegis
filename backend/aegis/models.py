"""Relational schema (M1). Migrations in backend/migrations are the source of truth for DDL;
these mappings must stay in sync (tests/test_schema_sync.py checks it)."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _now() -> Any:
    return func.now()


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=_now())


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    username: Mapped[str] = mapped_column(String(200), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    roles: Mapped[list[str]] = mapped_column(ARRAY(String(64)))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=_now())


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "producer_id",
            "source_adapter",
            "source_native_id",
            name="uq_security_events_source_identity",
        ),
    )
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    producer_id: Mapped[str] = mapped_column(String(120))
    source_adapter: Mapped[str] = mapped_column(String(64))
    source_adapter_version: Mapped[str] = mapped_column(String(32))
    source_native_id: Mapped[str] = mapped_column(String(200))
    schema_version: Mapped[str] = mapped_column(String(16))
    event_category: Mapped[str] = mapped_column(String(64))
    event_type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str | None] = mapped_column(String(16))
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=_now())
    asset_id: Mapped[str | None] = mapped_column(String(120))
    source_ip: Mapped[str | None] = mapped_column(INET)
    destination_ip: Mapped[str | None] = mapped_column(INET)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(32))
    principal: Mapped[str | None] = mapped_column(String(200))
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    origin: Mapped[str] = mapped_column(String(16))
    raw_event_reference: Mapped[str | None] = mapped_column(String(300))
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class WorkItem(Base):
    __tablename__ = "work_items"
    __table_args__ = (UniqueConstraint("kind", "ref_id", name="uq_work_items_kind_ref"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    kind: Mapped[str] = mapped_column(String(32))
    ref_id: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=_now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=_now())


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[Decimal] = mapped_column(Numeric(3, 2))
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB)
    mitre: Mapped[list[dict[str, str]]] = mapped_column(JSONB, default=list)
    author: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=_now())


class DetectionAlert(Base):
    __tablename__ = "detection_alerts"
    __table_args__ = (UniqueConstraint("tenant_id", "fingerprint", name="uq_alerts_fingerprint"),)
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    rule_id: Mapped[str] = mapped_column(String(80))
    rule_revision: Mapped[int] = mapped_column(Integer)
    fingerprint: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[Decimal] = mapped_column(Numeric(3, 2))
    group_key: Mapped[dict[str, Any]] = mapped_column(JSONB)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(Integer)
    first_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    explanation: Mapped[str] = mapped_column(Text)
    mitre: Mapped[list[dict[str, str]]] = mapped_column(JSONB, default=list)
    origin: Mapped[str] = mapped_column(String(16))
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=_now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=_now())


class AlertEvent(Base):
    __tablename__ = "alert_events"
    alert_id: Mapped[str] = mapped_column(ForeignKey("detection_alerts.id"), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("security_events.id"), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16))
    priority: Mapped[str] = mapped_column(String(4))
    correlation_rule: Mapped[str] = mapped_column(String(80))
    correlation_key: Mapped[str] = mapped_column(String(300))
    origin: Mapped[str] = mapped_column(String(16))
    version: Mapped[int] = mapped_column(Integer, default=1)
    assigned_to: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=_now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=_now())
    last_activity_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), primary_key=True)
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("detection_alerts.id"), primary_key=True, unique=True
    )
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=_now())


class IncidentTransition(Base):
    __tablename__ = "incident_transitions"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"))
    from_status: Mapped[str | None] = mapped_column(String(16))
    to_status: Mapped[str] = mapped_column(String(16))
    actor: Mapped[str] = mapped_column(String(200))
    reason: Mapped[str] = mapped_column(Text)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=_now())


class AuditLog(Base):
    __tablename__ = "audit_logs"
    # No RETURNING: pre-authentication rows (tenant_id NULL) are insertable but not readable
    # under RLS, and PostgreSQL applies SELECT policies to RETURNING.
    __table_args__ = {"implicit_returning": False}
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"))
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(80))
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(120))
    outcome: Mapped[str] = mapped_column(String(16))
    request_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=_now())
