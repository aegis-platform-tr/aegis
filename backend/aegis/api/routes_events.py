"""Event ingestion and retrieval, plus local-demo fixture import through the same path."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis import audit
from aegis.api.convert import event_out
from aegis.api.deps import require, tenant_session
from aegis.api.errors import ApiError
from aegis.api.pagination import DEFAULT_LIMIT, MAX_LIMIT, apply_keyset, encode_cursor
from aegis.api.schemas import EventOut, FixtureOut, IngestOut, ItemResultOut, Page
from aegis.config import Profile, Settings, get_settings
from aegis.contracts import EventBatchIn
from aegis.db import session_scope
from aegis.ingestion import ItemResult, ItemStatus, ingest_items
from aegis.models import SecurityEvent
from aegis.security import Capability, Principal

router = APIRouter(prefix="/api/v1", tags=["events"])
FIXTURE_NAME = re.compile(r"^[a-z0-9][a-z0-9\-]{1,62}$")


def _summarize(results: list[ItemResult]) -> IngestOut:
    return IngestOut(
        accepted=sum(r.status is ItemStatus.ACCEPTED for r in results),
        duplicate=sum(r.status is ItemStatus.DUPLICATE for r in results),
        rejected=sum(r.status is ItemStatus.REJECTED for r in results),
        results=[
            ItemResultOut(
                index=r.index, status=r.status.value, event_id=r.event_id, errors=r.errors
            )
            for r in results
        ],
    )


def _ingest(
    request: Request,
    principal: Principal,
    items: list[dict[str, Any]],
    producer_id: str,
    channel: str,
    settings: Settings,
) -> IngestOut:
    if len(items) > settings.max_batch_items:
        raise ApiError(413, "batch_too_large", f"Batch exceeds {settings.max_batch_items} items")
    with session_scope(tenant_id=principal.tenant_id) as s:
        results = ingest_items(
            s,
            tenant_id=principal.tenant_id,
            producer_id=producer_id,
            items=items,
            ingest_channel=channel,
        )
        out = _summarize(results)
        audit.record(
            s,
            tenant_id=principal.tenant_id,
            actor=principal.subject,
            action="events.ingest",
            outcome="success",
            target_type="event_batch",
            request_id=request.state.request_id,
            details={
                "channel": channel,
                "accepted": out.accepted,
                "duplicate": out.duplicate,
                "rejected": out.rejected,
            },
        )
    # Commit has completed here: a 200/207 response means durable acceptance.
    return out


@router.post(
    "/events",
    response_model=IngestOut,
    responses={207: {"description": "Some items were rejected"}},
)
def ingest_events(
    body: EventBatchIn,
    request: Request,
    principal: Principal = Depends(require(Capability.EVENTS_INGEST)),
    settings: Settings = Depends(get_settings),
) -> Any:
    from fastapi.responses import JSONResponse

    out = _ingest(request, principal, body.events, principal.subject, "api", settings)
    status = (
        207 if out.rejected and (out.accepted or out.duplicate) else (422 if out.rejected else 200)
    )
    return JSONResponse(out.model_dump(mode="json"), status_code=status)


@router.get("/events", response_model=Page[EventOut])
def list_events(
    principal: Principal = Depends(require(Capability.EVENTS_READ)),
    s: Session = Depends(tenant_session),
    cursor: str | None = None,
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    event_type: str | None = Query(None, max_length=64),
    origin: str | None = Query(None, pattern="^(synthetic|observed)$"),
    since: datetime | None = None,
    until: datetime | None = None,
) -> Page[EventOut]:
    conds = [SecurityEvent.tenant_id == principal.tenant_id]
    if event_type:
        conds.append(SecurityEvent.event_type == event_type)
    if origin:
        conds.append(SecurityEvent.origin == origin)
    if since:
        conds.append(SecurityEvent.ingested_at >= since)
    if until:
        conds.append(SecurityEvent.ingested_at < until)
    total = s.execute(select(func.count()).select_from(SecurityEvent).where(*conds)).scalar_one()
    stmt = apply_keyset(
        select(SecurityEvent).where(*conds),
        SecurityEvent.ingested_at,
        SecurityEvent.id,
        cursor,
        limit,
    )
    rows = list(s.scalars(stmt).all())
    nxt = (
        encode_cursor(rows[limit - 1].ingested_at, rows[limit - 1].id)
        if len(rows) > limit
        else None
    )
    return Page[EventOut](items=[event_out(e) for e in rows[:limit]], next_cursor=nxt, total=total)


@router.get("/events/{event_id}", response_model=EventOut)
def get_event(
    event_id: str,
    principal: Principal = Depends(require(Capability.EVENTS_READ)),
    s: Session = Depends(tenant_session),
) -> EventOut:
    e = s.execute(
        select(SecurityEvent).where(
            SecurityEvent.tenant_id == principal.tenant_id, SecurityEvent.id == event_id
        )
    ).scalar_one_or_none()
    if e is None:
        raise ApiError(404, "not_found", "Event not found")
    return event_out(e)


# ---- Local-demo fixture packs -------------------------------------------------------------


def _fixtures_dir(settings: Settings) -> Path:
    return Path(settings.fixtures_dir).resolve()


def _load_pack(settings: Settings, name: str) -> dict[str, Any]:
    if not FIXTURE_NAME.match(name):
        raise ApiError(404, "not_found", "Fixture pack not found")
    path = _fixtures_dir(settings) / f"{name}.json"
    if not path.is_file():
        raise ApiError(404, "not_found", "Fixture pack not found")
    pack: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if pack.get("origin") != "synthetic":
        raise ApiError(422, "fixture_not_synthetic", "Only packs labeled synthetic may be imported")
    return pack


def _require_demo(settings: Settings) -> None:
    if settings.profile is not Profile.LOCAL_DEMO:
        raise ApiError(403, "profile_forbidden", "Fixture import is only enabled in local-demo")


@router.get("/fixtures", response_model=list[FixtureOut])
def list_fixtures(
    principal: Principal = Depends(require(Capability.FIXTURES_IMPORT)),
    settings: Settings = Depends(get_settings),
) -> list[FixtureOut]:
    _require_demo(settings)
    out: list[FixtureOut] = []
    for path in sorted(_fixtures_dir(settings).glob("*.json")):
        try:
            pack = _load_pack(settings, path.stem)
            out.append(
                FixtureOut(
                    name=path.stem,
                    version=str(pack["version"]),
                    origin=pack["origin"],
                    description=pack["description"],
                    event_count=len(pack["events"]),
                )
            )
        except (ApiError, KeyError, ValueError, ValidationError):
            continue
    return out


@router.post("/fixtures/{name}/import", response_model=IngestOut)
def import_fixture(
    name: str,
    request: Request,
    principal: Principal = Depends(require(Capability.FIXTURES_IMPORT)),
    settings: Settings = Depends(get_settings),
) -> IngestOut:
    _require_demo(settings)
    pack = _load_pack(settings, name)
    events = pack.get("events")
    if not isinstance(events, list):
        raise ApiError(422, "invalid_fixture", "Fixture has no events list")
    # Producer is the pack, so any analyst in the tenant re-importing it is deduplicated.
    return _ingest(request, principal, events, f"fixture:{name}", "fixture-import", settings)
