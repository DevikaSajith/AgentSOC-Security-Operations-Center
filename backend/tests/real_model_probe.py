"""Manual real-model probe (not collected by pytest): real Ollama for Remediation only."""
import json, os
os.environ.setdefault("LLM_PROVIDER", "none")
from app.config import Settings
from app.llm.factory import build_provider
from app.llm.ollama import OllamaProvider
from app.database.connection import Database, create_db_engine
from app.database.models import Base
from app.simulator.cloud import CloudSimulator
from app.tools.base import ToolContext
from app.tools.executor import ToolExecutor
from app.tools.registry import build_default_registry
from tests.test_remediation import *  # noqa

engine = create_db_engine("sqlite://"); Base.metadata.create_all(engine); db = Database(engine); db.ensure_schema()
cloud = CloudSimulator(); audit = []
tools = ToolExecutor(ToolContext(cloud=cloud, database=db, registry=build_default_registry(), config_dir=CONFIG_DIR), audit_sink=audit.append)
iid = make_compliant(db, cloud, tools, audit)
provider = build_provider(Settings(llm_provider="ollama", llm_model="qwen3:4b"))
print("provider", provider.name, provider.model)
rep = plan(make_agent(db, tools, audit, provider), iid)
print(rep.status.value, rep.outcome, rep.method, "attempts", rep.attempts, rep.validation_errors[:2])
if rep.remediation:
    p = rep.remediation.plan
    print(json.dumps({"action": p.action.value, "target": p.target, "args": p.arguments, "risk": p.risk.value, "evidence": p.evidence_ids, "reason": p.reason, "effect": p.expected_effect, "notes": [n.field for n in p.policy_notes], "approval": rep.approval.status.value}, indent=1))
print("alice admin still", cloud.get_user("alice").admin)
