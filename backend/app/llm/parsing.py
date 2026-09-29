"""Extract a single JSON object from untrusted model text."""

import json
import re
from typing import Any

_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)
MAX_RESPONSE_CHARS = 20_000


class JSONExtractionError(ValueError):
    pass


def extract_json_object(text: str) -> dict[str, Any]:
    """The first JSON object in `text`. Reasoning tags and code fences are discarded."""
    if len(text) > MAX_RESPONSE_CHARS:
        raise JSONExtractionError(f"response longer than {MAX_RESPONSE_CHARS} characters")
    cleaned = _THINK.sub("", text).strip()
    fenced = _FENCE.search(cleaned)
    if fenced:
        cleaned = fenced.group(1).strip()
    start = cleaned.find("{")
    if start < 0:
        raise JSONExtractionError("no JSON object in the response")
    try:
        value, _ = json.JSONDecoder().raw_decode(cleaned[start:])
    except json.JSONDecodeError as exc:
        raise JSONExtractionError(f"invalid JSON: {exc.msg} at position {exc.pos}") from None
    if not isinstance(value, dict):
        raise JSONExtractionError("the response JSON is not an object")
    return value
