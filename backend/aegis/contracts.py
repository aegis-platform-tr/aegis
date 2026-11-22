"""Versioned event envelope (contracts/events). Python models are the source of truth;
contracts/events/*.schema.json is generated from them and checked for drift in tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0"})
# Events stamped further than this into the future are rejected as clock errors.
MAX_FUTURE_SKEW = timedelta(minutes=5)
MAX_ATTRIBUTES_BYTES = 16_384

Identifier = Annotated[str, Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9._:\-/@]+$")]
Token = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.\-]+$")]


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Origin(StrEnum):
    SYNTHETIC = "synthetic"
    OBSERVED = "observed"


class SourceRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    adapter: Token
    adapter_version: Annotated[str, Field(min_length=1, max_length=32)]
    native_id: Identifier = Field(
        description="Stable identifier assigned by the source or collector. Used for dedup."
    )


class EventIn(BaseModel):
    """Public ingest shape. Server-assigned fields (tenant_id, event_id, ingested_at) are
    forbidden: tenant scope always comes from the authenticated credential."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    event_category: Token
    event_type: Token
    severity: Severity | None = None
    occurred_at: datetime | None = Field(
        default=None, description="Source time. Null when the source does not provide it."
    )
    observed_at: datetime = Field(description="Collector time.")
    source: SourceRef
    asset_id: Identifier | None = None
    source_ip: IPv4Address | IPv6Address | None = None
    destination_ip: IPv4Address | IPv6Address | None = None
    source_port: Annotated[int, Field(ge=0, le=65535)] | None = None
    destination_port: Annotated[int, Field(ge=0, le=65535)] | None = None
    protocol: Token | None = None
    principal: Annotated[str, Field(max_length=200)] | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    origin: Origin
    raw_event_reference: Annotated[str, Field(max_length=300)] | None = None

    @field_validator("schema_version")
    @classmethod
    def _supported_version(cls, v: str) -> str:
        if v not in SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError(f"unsupported schema_version {v!r}")
        return v

    @field_validator("occurred_at", "observed_at")
    @classmethod
    def _tz_aware_not_future(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return v
        if v.tzinfo is None:
            raise ValueError("timestamps must include a timezone offset")
        if v - datetime.now(UTC) > MAX_FUTURE_SKEW:
            raise ValueError("timestamp is too far in the future")
        return v.astimezone(UTC)

    @model_validator(mode="after")
    def _bounded_attributes(self) -> EventIn:
        import json

        if len(json.dumps(self.attributes, default=str)) > MAX_ATTRIBUTES_BYTES:
            raise ValueError("attributes exceed size limit")
        return self


class EventBatchIn(BaseModel):
    """Batch wrapper. Items are validated individually so one bad item does not reject
    the whole batch (per-item result semantics, Section 21.2)."""

    model_config = ConfigDict(extra="forbid")
    events: list[dict[str, Any]] = Field(min_length=1)
