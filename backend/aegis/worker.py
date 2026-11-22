"""Background worker: claims work items with SKIP LOCKED and processes each in one
transaction (claim + detection + correlation + completion). A crash before commit rolls
everything back and the item is claimed again; repeated processing is idempotent."""

from __future__ import annotations

import logging
import signal
import time
from dataclasses import dataclass

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError

from aegis.correlation import correlate_alert
from aegis.db import session_scope, set_tenant
from aegis.detection import evaluate_event
from aegis.ingestion import WORK_KIND_EVALUATE
from aegis.models import SecurityEvent, WorkItem

log = logging.getLogger("aegis.worker")
MAX_ATTEMPTS = 5
IDLE_SLEEP_SECONDS = 1.0
MAX_ERROR_CHARS = 500


@dataclass
class RunStats:
    processed: int = 0
    failed: int = 0


def process_one() -> bool | None:
    """Process the next pending item. Returns True if processed, None if queue empty,
    False if the item failed (attempt recorded)."""
    claimed: tuple[int, str, str] | None = None
    try:
        with session_scope() as session:
            item = session.execute(
                select(WorkItem)
                .where(WorkItem.status == "pending")
                .order_by(WorkItem.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            ).scalar_one_or_none()
            if item is None:
                return None
            claimed = (item.id, item.tenant_id, item.ref_id)
            set_tenant(session, item.tenant_id)
            if item.kind != WORK_KIND_EVALUATE:
                raise ValueError(f"unknown work kind {item.kind!r}")
            event = session.execute(
                select(SecurityEvent).where(SecurityEvent.id == item.ref_id)
            ).scalar_one()
            for alert_id in evaluate_event(session, event):
                correlate_alert(session, alert_id)
            item.status = "done"
            item.attempts += 1
        log.info("work item processed", extra={"work_item_id": claimed[0], "event_id": claimed[2]})
        return True
    except (SQLAlchemyError, ValueError, LookupError) as exc:
        if claimed is None:
            raise
        _record_failure(claimed[0], exc)
        return False


def _safe_error(exc: Exception) -> str:
    """First line only: SQLAlchemy messages append SQL text and bound parameters, which can
    contain event data. Those must not be copied into the dead-letter table."""
    lines = str(exc).splitlines()
    first = lines[0] if lines else ""
    return f"{type(exc).__name__}: {first[:MAX_ERROR_CHARS]}"


def _record_failure(item_id: int, exc: Exception) -> None:
    log.warning("work item failed", extra={"work_item_id": item_id, "error": type(exc).__name__})
    with session_scope() as session:
        item = session.get(WorkItem, item_id)
        if item is None:
            return
        attempts = item.attempts + 1
        session.execute(
            update(WorkItem)
            .where(WorkItem.id == item_id)
            .values(
                attempts=attempts,
                status="dead" if attempts >= MAX_ATTEMPTS else "pending",
                last_error=_safe_error(exc),
            )
        )


def drain(max_items: int = 10_000) -> RunStats:
    """Process until the queue is empty (used by tests and the one-shot CLI)."""
    stats = RunStats()
    for _ in range(max_items):
        result = process_one()
        if result is None:
            break
        if result:
            stats.processed += 1
        else:
            stats.failed += 1
    return stats


def run_forever() -> None:
    stop = False

    def _stop(*_: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    log.info("worker started")
    while not stop:
        try:
            result = process_one()
        except SQLAlchemyError:
            log.exception("database unavailable; backing off")
            time.sleep(IDLE_SLEEP_SECONDS * 5)
            continue
        if result is None:
            time.sleep(IDLE_SLEEP_SECONDS)
    log.info("worker stopped")
