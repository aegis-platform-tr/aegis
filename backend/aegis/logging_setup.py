"""Structured JSON logging. Only explicitly whitelisted extra fields are emitted, so request
bodies, tokens and passwords never reach logs by accident."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

SAFE_EXTRA_FIELDS = ("request_id", "event_id", "work_item_id", "error", "tenant_id")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for name in SAFE_EXTRA_FIELDS:
            if hasattr(record, name):
                payload[name] = getattr(record, name)
        if record.exc_info:
            payload["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
