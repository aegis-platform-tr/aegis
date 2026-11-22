"""Credential masking at ingestion (Section 21.3). Keys that commonly carry secrets are
replaced before persistence. This is a minimization control, not a guarantee: secrets in
free-text values are not detected in M1 (documented limitation)."""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"
_SENSITIVE_KEY = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|authorization|cookie|session|private[_-]?key|credential)",
    re.IGNORECASE,
)
MAX_DEPTH = 8


def redact(value: Any, depth: int = 0) -> tuple[Any, list[str]]:
    """Return (redacted_copy, list_of_redacted_paths)."""
    paths: list[str] = []
    if depth > MAX_DEPTH:
        return REDACTED, ["<max-depth>"]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key = str(k)
            if _SENSITIVE_KEY.search(key):
                out[key] = REDACTED
                paths.append(key)
            else:
                child, child_paths = redact(v, depth + 1)
                out[key] = child
                paths.extend(f"{key}.{p}" for p in child_paths)
        return out, paths
    if isinstance(value, list):
        items: list[Any] = []
        for i, v in enumerate(value):
            child, child_paths = redact(v, depth + 1)
            items.append(child)
            paths.extend(f"[{i}].{p}" for p in child_paths)
        return items, paths
    return value, paths
