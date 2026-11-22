"""FastAPI application factory."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from aegis import __version__
from aegis.api import errors, routes_agents, routes_auth, routes_cases, routes_events
from aegis.config import get_settings
from aegis.db import session_scope
from aegis.logging_setup import configure_logging

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}
log = logging.getLogger("aegis.api")


@lru_cache(maxsize=1)
def migration_head() -> str | None:
    """Head revision of the migrations shipped with this build."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    return ScriptDirectory.from_config(cfg).get_current_head()


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    app = FastAPI(
        title="AEGIS API",
        version=__version__,
        description="AEGIS M1 vertical slice: ingestion, detection, correlation, incidents.",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        redoc_url=None,
    )
    errors.install(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        allow_credentials=False,
    )

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming = request.headers.get("x-request-id", "")
        rid = incoming if 8 <= len(incoming) <= 64 and incoming.isalnum() else uuid.uuid4().hex
        request.state.request_id = rid
        declared = request.headers.get("content-length")
        if declared is not None and (
            not declared.isdigit() or int(declared) > settings.max_body_bytes
        ):
            return JSONResponse(
                {
                    "error": {
                        "code": "payload_too_large",
                        "message": "Request body too large",
                        "correlation_id": rid,
                        "fields": [],
                    }
                },
                status_code=413,
            )
        if request.method in ("POST", "PATCH", "PUT") and declared is None:
            body = await request.body()  # bounded read for chunked uploads
            if len(body) > settings.max_body_bytes:
                return JSONResponse(
                    {
                        "error": {
                            "code": "payload_too_large",
                            "message": "Request body too large",
                            "correlation_id": rid,
                            "fields": [],
                        }
                    },
                    status_code=413,
                )
        if request.headers.get("content-encoding", "identity") not in ("identity", ""):
            return JSONResponse(
                {
                    "error": {
                        "code": "unsupported_encoding",
                        "message": "Compressed request bodies are not accepted",
                        "correlation_id": rid,
                        "fields": [],
                    }
                },
                status_code=415,
            )
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response

    @app.get("/api/v1/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/v1/ready", tags=["system"])
    def ready() -> Any:
        checks: dict[str, str] = {}
        try:
            with session_scope() as s:
                s.execute(text("SELECT 1"))
                head = s.execute(text("SELECT version_num FROM alembic_version")).scalar()
            checks["database"] = "ok"
            checks["migrations"] = "ok" if head == migration_head() else f"behind ({head})"
        except SQLAlchemyError:
            log.warning("readiness check failed: database unavailable")
            checks["database"] = "unavailable"
        ok = all(v == "ok" for v in checks.values())
        return JSONResponse(
            {
                "status": "ready" if ok else "not_ready",
                "checks": checks,
                "profile": settings.profile.value,
            },
            status_code=200 if ok else 503,
        )

    app.include_router(routes_auth.router)
    app.include_router(routes_events.router)
    app.include_router(routes_cases.router)
    app.include_router(routes_agents.router)
    return app
