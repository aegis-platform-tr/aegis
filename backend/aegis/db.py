"""Database engine and tenant-scoped sessions.

Tenant scope is applied twice (ADR-0002):
  1. Every repository query filters on tenant_id explicitly.
  2. PostgreSQL row-level security policies read the transaction-local setting
     ``aegis.tenant_id``; the runtime role is not the table owner, so RLS applies.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from aegis.config import get_settings


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    url = get_settings().database_url.get_secret_value()
    return create_engine(
        url,
        pool_pre_ping=True,
        hide_parameters=True,  # bound values (event data) never appear in error text/logs
        pool_size=5,
        max_overflow=5,
        connect_args={"options": "-c timezone=UTC -c statement_timeout=15000"},
    )


@lru_cache(maxsize=1)
def _session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def set_tenant(session: Session, tenant_id: str) -> None:
    """Bind RLS tenant scope for the current transaction only (is_local = true)."""
    session.execute(text("SELECT set_config('aegis.tenant_id', :t, true)"), {"t": tenant_id})


@contextmanager
def session_scope(tenant_id: str | None = None) -> Iterator[Session]:
    """Transactional session. Commits on success, rolls back on any exception."""
    session = _session_factory()()
    try:
        with session.begin():
            if tenant_id is not None:
                set_tenant(session, tenant_id)
            yield session
    finally:
        session.close()
