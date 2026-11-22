"""Alembic environment. Uses the migration (owner) role, never the runtime role.

Concurrent startups are serialized with a PostgreSQL advisory lock so migrations apply exactly
once even if several containers start at the same time.
"""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import create_engine, text

MIGRATION_LOCK_KEY = 7_311_001  # arbitrary constant, unique to AEGIS migrations


def _url() -> str:
    url = os.environ.get("AEGIS_MIGRATION_DATABASE_URL")
    if not url:
        raise RuntimeError("AEGIS_MIGRATION_DATABASE_URL is not set")
    return url


def run_migrations_online() -> None:
    engine = create_engine(_url())
    with engine.connect() as connection:
        connection.execute(text("SELECT pg_advisory_lock(:k)"), {"k": MIGRATION_LOCK_KEY})
        connection.commit()
        try:
            context.configure(connection=connection, target_metadata=None)
            with context.begin_transaction():
                context.run_migrations()
            connection.commit()
        finally:
            connection.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": MIGRATION_LOCK_KEY})
            connection.commit()
    engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("Offline SQL generation is not supported for AEGIS migrations")
run_migrations_online()
