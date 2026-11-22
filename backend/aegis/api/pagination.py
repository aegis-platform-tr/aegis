"""Keyset (cursor) pagination with a stable (timestamp DESC, id DESC) ordering."""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any

from sqlalchemy import Select, and_, or_
from sqlalchemy.orm import InstrumentedAttribute

from aegis.api.errors import ApiError

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


def encode_cursor(ts: datetime, row_id: str) -> str:
    raw = json.dumps({"t": ts.isoformat(), "id": row_id}).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded))
        return datetime.fromisoformat(data["t"]), str(data["id"])
    except (ValueError, KeyError, TypeError) as exc:
        raise ApiError(400, "invalid_cursor", "Malformed pagination cursor") from exc


def apply_keyset(
    stmt: Select[Any],
    ts_col: InstrumentedAttribute[datetime],
    id_col: InstrumentedAttribute[str],
    cursor: str | None,
    limit: int,
) -> Select[Any]:
    if cursor:
        ts, row_id = decode_cursor(cursor)
        stmt = stmt.where(or_(ts_col < ts, and_(ts_col == ts, id_col < row_id)))
    return stmt.order_by(ts_col.desc(), id_col.desc()).limit(limit + 1)
