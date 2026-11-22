"""Deterministic content inspection used by the AI gateway (input and output).

These checks produce *signals about evidence*, not judgments of intent. An "injection signal"
means the text contains patterns commonly used to redirect a model; it does not establish
that anyone attempted an attack. The pattern lists are intentionally small, documented and
evaluated (docs/evaluation/ai-gateway.md); they are not a complete defense.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

REDACTION = "[REDACTED:{kind}]"

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"
        ),
    ),
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aegis_credential", re.compile(r"\baegis_(agt|enr)_[A-Za-z0-9_\-]{20,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}")),
    (
        "password_assignment",
        re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*[^\s'\"]{6,}"),
    ),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
]

INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "override_instructions",
        re.compile(
            r"(?i)\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|all|earlier)\b"
            r"[^.\n]{0,20}\b(instructions?|rules?|prompts?|directions?)"
        ),
    ),
    (
        "role_reassignment",
        re.compile(
            r"(?i)\b(you are now|from now on you|act as (an? )?(admin|administrator|root|system))"
        ),
    ),
    ("fake_role_marker", re.compile(r"(?im)^\s*(system|assistant|developer)\s*:\s*\S")),
    (
        "tool_coercion",
        re.compile(
            r"(?i)\b(call|invoke|execute|run|use)\b[^.\n]{0,30}\b(tool|function|propose_block|"
            r"shell|command)\b"
        ),
    ),
    (
        "exfiltration_request",
        re.compile(
            r"(?i)\b(reveal|print|show|send|exfiltrate|leak)\b[^.\n]{0,40}\b(system prompt|"
            r"credentials?|secrets?|api keys?|passwords?)"
        ),
    ),
]

SHELL_IN_OUTPUT = re.compile(
    r"(?im)(^|\s)(rm\s+-rf|curl\s+[^|]*\|\s*(ba)?sh|wget\s+[^|]*\|\s*(ba)?sh|nc\s+-e|"
    r"powershell\s+-enc)"
)


@dataclass(frozen=True)
class Finding:
    check: str
    kind: str
    location: str  # "prompt" | "document[0]" | "output" ...

    def as_dict(self) -> dict[str, str]:
        return {"check": self.check, "kind": self.kind, "location": self.location}


def find_secrets(text: str, location: str) -> list[Finding]:
    return [Finding("secret", kind, location) for kind, pat in SECRET_PATTERNS if pat.search(text)]


def redact_secrets(text: str) -> str:
    for kind, pat in SECRET_PATTERNS:
        text = pat.sub(REDACTION.format(kind=kind), text)
    return text


def find_injection(text: str, location: str) -> list[Finding]:
    return [
        Finding("injection_signal", kind, location)
        for kind, pat in INJECTION_PATTERNS
        if pat.search(text)
    ]


def find_shell(text: str, location: str) -> list[Finding]:
    return (
        [Finding("unsafe_instruction", "shell_command", location)]
        if SHELL_IN_OUTPUT.search(text)
        else []
    )
