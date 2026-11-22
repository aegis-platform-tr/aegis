"""Operator entry points: python -m aegis.cli <command>."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

CONTRACT_PATH = (
    Path(__file__).resolve().parents[2] / "contracts/events/event-envelope.v1.schema.json"
)

DEV_TENANTS = [
    ("tenant_demo", "Demo Tenant (development only)"),
    ("tenant_other", "Second Tenant (isolation tests, development only)"),
]
DEV_USERS = [
    ("analyst@demo.local", "tenant_demo", ["analyst"]),
    ("viewer@demo.local", "tenant_demo", ["viewer"]),
    ("auditor@demo.local", "tenant_demo", ["auditor"]),
    ("admin@demo.local", "tenant_demo", ["tenant_admin"]),
    ("maintainer@demo.local", "tenant_demo", ["detection_maintainer"]),
    ("proposer@demo.local", "tenant_demo", ["analyst", "response_proposer"]),
    ("approver@demo.local", "tenant_demo", ["response_approver"]),
    ("lead@demo.local", "tenant_demo", ["response_proposer", "response_approver"]),
    ("analyst@other.local", "tenant_other", ["analyst"]),
]


def cmd_migrate(_: argparse.Namespace) -> int:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    command.upgrade(cfg, "head")
    print("migrations: at head")
    return 0


def cmd_seed_dev(_: argparse.Namespace) -> int:
    """Provision DEVELOPMENT-ONLY tenants and users. Refuses outside local-demo."""
    from sqlalchemy import select

    from aegis.config import Profile, get_settings
    from aegis.db import session_scope
    from aegis.models import Tenant, User
    from aegis.security import hash_password

    settings = get_settings()
    if settings.profile is not Profile.LOCAL_DEMO:
        print("refusing: seed-dev only runs with AEGIS_PROFILE=local-demo", file=sys.stderr)
        return 2
    password = os.environ.get("AEGIS_DEV_PASSWORD", "")
    if len(password) < 12:
        print(
            "refusing: set AEGIS_DEV_PASSWORD (>= 12 chars) for development users", file=sys.stderr
        )
        return 2
    with session_scope() as s:
        for tid, name in DEV_TENANTS:
            if s.get(Tenant, tid) is None:
                s.add(Tenant(id=tid, name=name))
        s.flush()
        for username, tid, roles in DEV_USERS:
            existing = s.execute(select(User).where(User.username == username)).scalar_one_or_none()
            if existing is None:
                s.add(
                    User(
                        username=username,
                        tenant_id=tid,
                        roles=roles,
                        password_hash=hash_password(password),
                    )
                )
    _seed_resources()
    print(
        f"seeded {len(DEV_TENANTS)} tenants and {len(DEV_USERS)} development users "
        f"(password from AEGIS_DEV_PASSWORD; development only)"
    )
    return 0


def _seed_resources() -> None:
    """One simulation resource per dev tenant (host state is never touched)."""
    from sqlalchemy import select

    from aegis.db import session_scope
    from aegis.models import ManagedResource

    for tid, _ in DEV_TENANTS:
        with session_scope(tenant_id=tid) as s:
            exists = s.execute(
                select(ManagedResource.id).where(
                    ManagedResource.tenant_id == tid, ManagedResource.name == "lab-edge (simulated)"
                )
            ).first()
            if not exists:
                s.add(
                    ManagedResource(
                        id=f"res_sim_{tid}",
                        tenant_id=tid,
                        name="lab-edge (simulated)",
                        adapter="simulation",
                        interface="eth0",
                        protected_cidrs=["198.51.100.0/28", "192.0.2.250/32"],
                        enabled=True,
                        live_writes_enabled=False,
                        policy_revision=1,
                        policy_snapshot={"rules": []},
                        created_by="seed-dev",
                    )
                )


def cmd_worker(args: argparse.Namespace) -> int:
    from aegis.config import get_settings
    from aegis.logging_setup import configure_logging
    from aegis.worker import drain, run_forever

    configure_logging(get_settings().log_level)
    if args.once:
        stats = drain()
        print(json.dumps({"processed": stats.processed, "failed": stats.failed}))
    else:
        run_forever()
    return 0


def cmd_ai_eval(args: argparse.Namespace) -> int:
    """Run the AI gateway evaluation set against the configured (local-demo) database through
    the real API and write the markdown report."""
    import os
    from pathlib import Path

    from fastapi.testclient import TestClient

    from aegis.ai import evaluate
    from aegis.api.app import create_app
    from aegis.worker import drain

    pw = os.environ.get("AEGIS_DEV_PASSWORD", "")
    with TestClient(create_app()) as c:

        def login(user: str) -> dict[str, str]:
            r = c.post("/api/v1/auth/login", json={"username": user, "password": pw})
            return {"Authorization": f"Bearer {r.json()['access_token']}"}

        c.post("/api/v1/fixtures/auth-bruteforce-demo/import", headers=login("analyst@demo.local"))
        drain()
        inc = c.get("/api/v1/incidents", headers=login("analyst@demo.local")).json()["items"][0]
        other = c.post(
            "/api/v1/fixtures/auth-bruteforce-demo/import", headers=login("analyst@other.local")
        ).json()
        drain()
        evs = c.get("/api/v1/events?limit=1", headers=login("analyst@other.local")).json()
        _ = other
        results = evaluate.run(c, login, inc["incident_id"], evs["items"][0]["event_id"])
    text = evaluate.report(results)
    Path(args.out).write_text(text)
    print(text)
    return 1 if any(r["status"] == "fail" for r in results) else 0


def cmd_api(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "aegis.api.app:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        log_config=None,
        proxy_headers=False,
    )
    return 0


def cmd_export_schema(args: argparse.Namespace) -> int:
    from aegis.contracts import EventIn

    schema = EventIn.model_json_schema()
    schema["$id"] = "https://aegis.local/contracts/events/event-envelope.v1.schema.json"
    schema["title"] = "AEGIS event envelope v1 (public ingest shape)"
    text = json.dumps(schema, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not CONTRACT_PATH.exists() or CONTRACT_PATH.read_text() != text:
            print("contract drift: run `python -m aegis.cli export-schema`", file=sys.stderr)
            return 1
        print("contract: up to date")
        return 0
    CONTRACT_PATH.write_text(text)
    print(f"wrote {CONTRACT_PATH}")
    return 0


def cmd_import_fixture(args: argparse.Namespace) -> int:
    """Import a fixture through the public authenticated /events API (normal ingest path)."""
    pack = json.loads(Path(args.file).read_text(encoding="utf-8"))
    password = os.environ.get("AEGIS_IMPORT_PASSWORD") or os.environ.get("AEGIS_DEV_PASSWORD", "")

    def call(path: str, body: dict[str, object], token: str | None = None) -> dict[str, object]:
        if not args.api.startswith(("http://127.0.0.1", "http://localhost", "https://")):
            raise SystemExit("refusing non-local plain-HTTP API URL")
        req = urllib.request.Request(  # noqa: S310 - scheme checked above
            args.api.rstrip("/") + path,
            data=json.dumps(body).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                **({"Authorization": f"Bearer {token}"} if token else {}),
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            result: dict[str, object] = json.loads(resp.read())
            return result

    login = call("/api/v1/auth/login", {"username": args.username, "password": password})
    out = call("/api/v1/events", {"events": pack["events"]}, str(login["access_token"]))
    print(json.dumps({k: out[k] for k in ("accepted", "duplicate", "rejected")}))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aegis")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate").set_defaults(fn=cmd_migrate)
    sub.add_parser("seed-dev").set_defaults(fn=cmd_seed_dev)
    w = sub.add_parser("worker")
    w.add_argument("--once", action="store_true", help="drain the queue and exit")
    w.set_defaults(fn=cmd_worker)
    a = sub.add_parser("api")
    a.add_argument("--host", default="127.0.0.1")
    a.add_argument("--port", type=int, default=8000)
    a.set_defaults(fn=cmd_api)
    ev = sub.add_parser("ai-eval")
    ev.add_argument("--out", default="../docs/evaluation/ai-gateway.md")
    ev.set_defaults(fn=cmd_ai_eval)
    e = sub.add_parser("export-schema")
    e.add_argument("--check", action="store_true")
    e.set_defaults(fn=cmd_export_schema)
    f = sub.add_parser("import-fixture")
    f.add_argument("file")
    f.add_argument("--api", default="http://127.0.0.1:8000")
    f.add_argument("--username", default="analyst@demo.local")
    f.set_defaults(fn=cmd_import_fixture)
    args = p.parse_args(argv)
    result: int = args.fn(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
