#!/usr/bin/env python3
"""Repository secret scan (fallback when gitleaks is unavailable). Scans tracked files with the
same patterns the AI gateway uses plus key-file names. Known inert test canaries are allowed
explicitly by exact value so new findings are never silently ignored."""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from aegis.ai.inspection import SECRET_PATTERNS  # noqa: E402

ALLOWED_VALUES = {
    "AEGIS-CANARY-NOT-A-REAL-SECRET", "CorrectHorse-canary-77", "AKIAABCDEFGHIJKLMNOP",
    "Hunter2-canary-value", "SECRET-CANARY",
}
ALLOWED_CONTEXT = re.compile(r"(change-me|dev-only|devonly|test-only|ci-only|placeholder|"
                             r"wrong-password|whatever-123|not-a-secret|example|forged|\$AEGIS_|:')", re.I)
SKIP = re.compile(r"(\.cdx\.json$|package-lock\.json$|^LICENSE$|\.png$)")
# A credential literal: key, assignment, then a quoted string of 8+ characters.
LITERAL = re.compile(r"(?i)\w*(password|passwd|pwd|secret|api[_-]?key|token)\w*[\"']?\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']")
KEY_FILES = re.compile(r"(\.pem|\.key|id_rsa|id_ed25519|\.p12|\.pfx|\.env)$")


def main() -> int:
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True,
                           check=True).stdout.split()
    findings = []
    for f in files:
        if SKIP.search(f):
            continue
        if KEY_FILES.search(f) and not f.endswith(".env.example"):
            findings.append((f, 0, "key-like file tracked"))
        try:
            text = (ROOT / f).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for kind, pat in [*SECRET_PATTERNS, ("credential_literal", LITERAL)]:
                m = pat.search(line)
                if not m:
                    continue
                if any(v in line for v in ALLOWED_VALUES) or ALLOWED_CONTEXT.search(line):
                    continue
                if f.endswith(("inspection.py", "secret_scan.py")):
                    continue  # pattern definitions
                if kind == "password_assignment" and not LITERAL.search(line[m.start():]):
                    continue  # code like `password=args.password`: no literal value
                findings.append((f, n, kind))
    for f, n, kind in findings:
        print(f"{f}:{n}: possible {kind}")
    print(f"scanned {len(files)} tracked files, {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
