"""Idempotent ingestion (ADR-0004).

The event row and its downstream work marker are written in the same transaction. A
successful response means durable acceptance. Replays with the same
(tenant, producer, source.adapter, source.native_id) resolve to the original event_id.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from aegis.contracts import EventIn
from aegis.models import SecurityEvent, WorkItem
from aegis.redaction import redact

WORK_KIND_EVALUATE = "evaluate_event"


class ItemStatus(StrEnum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"  # permanent: fix the payload before retrying


@dataclass
class ItemResult:
    index: int
    status: ItemStatus
    event_id: str | None = None
    errors: list[dict[str, Any]] = field(default_factory=list)


def new_event_id() -> str:
    return f"evt_{uuid.uuid4().hex}"


def _safe_errors(exc: ValidationError) -> list[dict[str, Any]]:
    # Never echo submitted values back (they may contain secrets).
    return [
        {"field": ".".join(str(p) for p in e["loc"]), "code": e["type"], "message": e["msg"]}
        for e in exc.errors(include_input=False, include_url=False)
    ]


def ingest_items(
    session: Session,
    *,
    tenant_id: str,
    producer_id: str,
    items: list[dict[str, Any]],
    ingest_channel: str,
) -> list[ItemResult]:
    results: list[ItemResult] = []
    for index, raw in enumerate(items):
        try:
            event = EventIn.model_validate(raw)
        except ValidationError as exc:
            results.append(ItemResult(index, ItemStatus.REJECTED, errors=_safe_errors(exc)))
            continue
        results.append(_persist(session, tenant_id, producer_id, event, index, ingest_channel))
    return results


def _persist(
    session: Session,
    tenant_id: str,
    producer_id: str,
    event: EventIn,
    index: int,
    ingest_channel: str,
) -> ItemResult:
    attributes, redacted_paths = redact(event.attributes)
    event_id = new_event_id()
    stmt = (
        pg_insert(SecurityEvent)
        .values(
            id=event_id,
            tenant_id=tenant_id,
            producer_id=producer_id,
            source_adapter=event.source.adapter,
            source_adapter_version=event.source.adapter_version,
            source_native_id=event.source.native_id,
            schema_version=event.schema_version,
            event_category=event.event_category,
            event_type=event.event_type,
            severity=event.severity.value if event.severity else None,
            occurred_at=event.occurred_at,
            observed_at=event.observed_at,
            asset_id=event.asset_id,
            source_ip=str(event.source_ip) if event.source_ip else None,
            destination_ip=str(event.destination_ip) if event.destination_ip else None,
            source_port=event.source_port,
            destination_port=event.destination_port,
            protocol=event.protocol,
            principal=event.principal,
            attributes=attributes,
            origin=event.origin.value,
            raw_event_reference=event.raw_event_reference,
            provenance={
                "ingest_channel": ingest_channel,
                "producer_id": producer_id,
                "redacted_fields": redacted_paths,
                "time_quality": "source" if event.occurred_at else "collector_only",
            },
        )
        .on_conflict_do_nothing(constraint="uq_security_events_source_identity")
        .returning(SecurityEvent.id)
    )
    inserted = session.execute(stmt).scalar_one_or_none()
    if inserted is not None:
        session.add(WorkItem(tenant_id=tenant_id, kind=WORK_KIND_EVALUATE, ref_id=inserted))
        session.flush()
        return ItemResult(index, ItemStatus.ACCEPTED, event_id=inserted)

    existing = session.execute(
        select(SecurityEvent.id).where(
            SecurityEvent.tenant_id == tenant_id,
            SecurityEvent.producer_id == producer_id,
            SecurityEvent.source_adapter == event.source.adapter,
            SecurityEvent.source_native_id == event.source.native_id,
        )
    ).scalar_one()
    return ItemResult(index, ItemStatus.DUPLICATE, event_id=existing)
