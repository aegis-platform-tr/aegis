"""Stable structured error format: {"error": {code, message, correlation_id, fields}}.
Client errors never include stack traces, SQL or submitted values."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("aegis.api")


class ApiError(Exception):
    def __init__(
        self, status: int, code: str, message: str, fields: list[dict[str, Any]] | None = None
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.fields = fields or []


def _body(
    request: Request, code: str, message: str, fields: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "correlation_id": getattr(request.state, "request_id", None),
            "fields": fields,
        }
    }


def install(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            _body(request, exc.code, exc.message, exc.fields), status_code=exc.status
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        fields = [
            {
                "field": ".".join(str(p) for p in e.get("loc", ())),
                "code": e.get("type", "invalid"),
                "message": e.get("msg", "invalid"),
            }
            for e in exc.errors()
        ]
        return JSONResponse(
            _body(request, "validation_failed", "Request validation failed", fields),
            status_code=422,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return JSONResponse(_body(request, code, str(exc.detail), []), status_code=exc.status_code)

    @app.exception_handler(OperationalError)
    async def _db_down(request: Request, exc: OperationalError) -> JSONResponse:
        log.warning(
            "database unavailable", extra={"request_id": getattr(request.state, "request_id", None)}
        )
        return JSONResponse(
            _body(request, "dependency_unavailable", "A required dependency is unavailable", []),
            status_code=503,
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception(
            "unhandled error", extra={"request_id": getattr(request.state, "request_id", None)}
        )
        return JSONResponse(
            _body(request, "internal_error", "Internal server error", []), status_code=500
        )
