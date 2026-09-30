"""BEFORE / EXPECTED / ACTUAL comparison. Pure functions: no I/O, no cloud access, no model."""

from typing import Any

from app.domain.verification import FieldComparison, VerificationStatus


def compare(before: dict[str, Any] | None, expected: dict[str, Any], actual: dict[str, Any]) -> list[FieldComparison]:
    """One row per expected field, using the state as it is NOW. Values are compared exactly (no truthiness)."""
    rows = []
    for name, want in expected.items():
        present = name in actual
        have = actual.get(name)
        was = (before or {}).get(name)
        rows.append(FieldComparison(
            field=name, before=was, expected=want, actual=have, present=present,
            satisfied=present and have == want and type(have) is type(want),
            changed_from_before=(before is not None and name in before and was != have)))
    return rows


def classify(rows: list[FieldComparison]) -> VerificationStatus:
    """verified: all hold. failed: none holds. partial: some hold. unknown: a field is missing from the state
    (uncertainty is never converted into success)."""
    if not rows or any(not r.present for r in rows):
        return VerificationStatus.UNKNOWN
    held = sum(r.satisfied for r in rows)
    if held == len(rows):
        return VerificationStatus.VERIFIED
    return VerificationStatus.FAILED if held == 0 else VerificationStatus.PARTIAL
