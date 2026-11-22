"""Response models (OpenAPI contract)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=1024)


class UserOut(BaseModel):
    username: str
    tenant_id: str
    roles: list[str]
    capabilities: list[str]


class TokenOut(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth token type, not a secret
    expires_at: datetime
    user: UserOut


class ItemResultOut(BaseModel):
    index: int
    status: Literal["accepted", "duplicate", "rejected"]
    event_id: str | None = None
    errors: list[dict[str, Any]] = Field(default_factory=list)


class IngestOut(BaseModel):
    accepted: int
    duplicate: int
    rejected: int
    results: list[ItemResultOut]


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    event_id: str
    schema_version: str
    event_category: str
    event_type: str
    severity: str | None
    occurred_at: datetime | None
    observed_at: datetime
    ingested_at: datetime
    source: dict[str, str]
    producer_id: str
    asset_id: str | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    principal: str | None
    attributes: dict[str, Any]
    origin: str
    raw_event_reference: str | None
    provenance: dict[str, Any]


class AlertOut(BaseModel):
    alert_id: str
    rule_id: str
    rule_revision: int
    title: str
    severity: str
    confidence: float
    group_key: dict[str, Any]
    window_start: datetime
    window_end: datetime
    event_count: int
    first_event_at: datetime
    last_event_at: datetime
    evaluated_at: datetime
    explanation: str
    mitre: list[dict[str, str]]
    origin: str
    suppressed: bool = False
    suppression_id: str | None = None
    evidence_quality: str = "direct"
    incident_id: str | None = None
    event_ids: list[str] | None = None


class IncidentOut(BaseModel):
    incident_id: str
    title: str
    status: str
    severity: str
    priority: str
    correlation_rule: str
    correlation_key: str
    origin: str
    version: int
    assigned_to: str | None
    created_at: datetime
    updated_at: datetime
    last_activity_at: datetime
    alert_count: int


class TimelineEntry(BaseModel):
    kind: Literal["event", "alert", "transition", "note"]
    at: datetime
    ref_id: str
    summary: str
    times: dict[str, datetime | None]
    origin: str | None = None


class IncidentDetailOut(IncidentOut):
    alerts: list[AlertOut]
    timeline: list[TimelineEntry]


class IncidentPatchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["new", "investigating", "contained", "resolved", "closed"]
    version: int = Field(ge=1, description="Current version; mismatches return 409")
    reason: str = Field(min_length=3, max_length=2000)


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["note", "containment_verification", "closure_reason"] = "note"
    body: str = Field(min_length=1, max_length=10000)


class AssignIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assignee: str | None = Field(default=None, max_length=200)
    version: int = Field(ge=1)


class Page[T](BaseModel):
    items: list[T]
    next_cursor: str | None
    total: int


class AuditOut(BaseModel):
    id: int
    actor: str
    action: str
    target_type: str | None
    target_id: str | None
    outcome: str
    request_id: str | None
    details: dict[str, Any]
    at: datetime


class FixtureOut(BaseModel):
    name: str
    version: str
    origin: str
    description: str
    event_count: int
