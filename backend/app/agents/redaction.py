"""Redaction helpers for anything an LLM may see (shared by reasoning agents)."""

import re
from typing import Any

# Keys whose values must never reach a model (matched case-insensitively, any depth).
_SENSITIVE_KEY = re.compile(r"(key_?id|secret|password|passwd|token|credential|private|"
                            r"session|signature|authorization|api_?key)", re.IGNORECASE)
# Values that look like AWS access key IDs (real or simulated).
_KEY_VALUE = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{8,}\b")
REDACTED = "[redacted]"
# Simulator ground truth (and ingest bookkeeping) never shown to agents.
GROUND_TRUTH_KEYS = frozenset({"scenario_id", "step", "state_change", "ingest"})


def sanitize(value: Any, max_len: int = 240) -> Any:
    """Recursively drop sensitive keys, mask key-ID-like values and truncate strings."""
    if isinstance(value, dict):
        return {k: sanitize(v, max_len) for k, v in value.items() if not _SENSITIVE_KEY.search(str(k))}
    if isinstance(value, list):
        return [sanitize(v, max_len) for v in value]
    if isinstance(value, str):
        masked = _KEY_VALUE.sub(REDACTED, value)
        return masked if len(masked) <= max_len else masked[:max_len] + "…"
    return value


def summarize_iam_user(state: dict[str, Any]) -> dict[str, Any]:
    """An IAM user's state without key identifiers."""
    keys = state.get("access_keys") or []
    return {
        "name": state.get("name"), "role": state.get("role"), "admin": state.get("admin"),
        "access_keys_total": len(keys), "access_keys_active": sum(1 for k in keys if k.get("active")),
        "access_key_last_used_ips": sorted({k["last_used_ip"] for k in keys if k.get("last_used_ip")}),
    }
