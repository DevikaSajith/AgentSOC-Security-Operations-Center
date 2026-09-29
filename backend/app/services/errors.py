"""Storage errors shared by all services (messages never contain credentials)."""

import logging
from typing import NoReturn

from sqlalchemy.exc import OperationalError, SQLAlchemyError

logger = logging.getLogger(__name__)


class DatabaseUnavailableError(RuntimeError):
    """The database cannot be reached."""


class EventStorageError(RuntimeError):
    """A database operation failed for another reason (message is credential-free)."""


def raise_storage_error(exc: SQLAlchemyError) -> NoReturn:
    """Translate a SQLAlchemy error into one of the errors above."""
    # Never include str(exc): SQLAlchemy messages can contain connection details.
    logger.error("database error: %s", type(exc).__name__)
    if isinstance(exc, OperationalError):
        raise DatabaseUnavailableError("database is unavailable") from exc
    raise EventStorageError("database operation failed") from exc
