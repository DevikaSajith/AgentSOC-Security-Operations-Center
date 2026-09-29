"""Database engine and session management.

Works with SQLite (the default) and PostgreSQL; the dialect comes from DATABASE_URL.
"""

import logging
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Any, Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import safe_database_url
from app.database.models import Base

logger = logging.getLogger(__name__)


def _enable_sqlite_foreign_keys(dbapi_connection: Any, _: Any) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def create_db_engine(url: str) -> Engine:
    """Create an engine with the right options for the URL's dialect."""
    parsed = make_url(url)
    if parsed.get_backend_name() != "sqlite":
        return create_engine(url, pool_pre_ping=True)

    kwargs: dict[str, Any] = {
        # FastAPI runs sync endpoints in a threadpool; SQLite must allow that.
        "connect_args": {"check_same_thread": False},
    }
    database = parsed.database
    if not database or database == ":memory:":
        # One shared connection, otherwise every connection gets its own empty DB.
        kwargs["poolclass"] = StaticPool
    else:
        Path(database).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, **kwargs)
    event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    return engine


class Database:
    """Wraps an engine + session factory and creates the schema once."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self._session_factory = sessionmaker(bind=engine, expire_on_commit=False)
        self._schema_ready = False
        self._lock = Lock()

    @classmethod
    def from_url(cls, url: str) -> "Database":
        """Create a Database from a SQLAlchemy URL (connects lazily)."""
        logger.info("using database %s", safe_database_url(url))
        return cls(create_db_engine(url))

    @property
    def backend_name(self) -> str:
        """'sqlite', 'postgresql', ..."""
        return self.engine.dialect.name

    def ensure_schema(self) -> None:
        """Create tables if needed. Raises SQLAlchemyError if the DB is unreachable."""
        with self._lock:
            if not self._schema_ready:
                Base.metadata.create_all(self.engine)
                self._schema_ready = True
                logger.info("database schema ready (%s)", self.backend_name)

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Yield a session and always close it."""
        session = self._session_factory()
        try:
            yield session
        finally:
            session.close()
