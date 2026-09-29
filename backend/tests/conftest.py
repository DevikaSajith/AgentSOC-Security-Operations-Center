"""Shared fixtures.

If TEST_DATABASE_URL is set, tests use that database (tables are dropped and recreated per
test - never point it at real data). Otherwise they use in-memory SQLite.
"""

import os

# Importing app.main builds a module-level app; keep it off the developer's DB file.
os.environ.setdefault("DATABASE_URL", "sqlite://")
# Tests never talk to a real LLM: providers are injected (MockLLMProvider) where needed.
os.environ["LLM_PROVIDER"] = "none"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import Settings  # noqa: E402
from app.database.connection import Database, create_db_engine  # noqa: E402
from app.database.models import Base  # noqa: E402
from app.main import create_app  # noqa: E402
from app.simulator.attacks import AttackSimulator  # noqa: E402
from app.simulator.cloud import CloudSimulator  # noqa: E402
from app.tools.base import ToolContext  # noqa: E402
from app.tools.executor import ToolExecutor  # noqa: E402
from app.tools.registry import build_default_registry  # noqa: E402


@pytest.fixture()
def database() -> Database:
    engine = create_db_engine(os.getenv("TEST_DATABASE_URL") or "sqlite://")
    Base.metadata.drop_all(engine)
    db = Database(engine)
    db.ensure_schema()
    yield db
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture()
def cloud() -> CloudSimulator:
    return CloudSimulator()


@pytest.fixture()
def attacks(cloud: CloudSimulator) -> AttackSimulator:
    return AttackSimulator(cloud)


@pytest.fixture()
def client(cloud: CloudSimulator, database: Database) -> TestClient:
    with TestClient(create_app(cloud=cloud, database=database, settings=Settings())) as c:
        yield c


@pytest.fixture()
def audit_log() -> list:
    return []


@pytest.fixture()
def executor(cloud: CloudSimulator, database: Database, audit_log: list) -> ToolExecutor:
    context = ToolContext(cloud=cloud, database=database, registry=build_default_registry(),
                          config_dir=Settings().config_dir)
    return ToolExecutor(context, audit_sink=audit_log.append)
