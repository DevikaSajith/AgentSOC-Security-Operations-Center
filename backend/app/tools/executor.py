"""The single choke point through which every tool call passes.

    ToolRequest -> known tool? -> arguments valid? -> actor permitted?
                -> (ACTION) human approval present and matching? -> handler

Every request, allowed or not, produces a ToolExecutionResult and an audit entry.
"""

import logging
from typing import Callable

from pydantic import ValidationError

from app.domain.enums import ApprovalStatus, HumanActor
from app.domain.incident import AuditEntry
from app.tools.base import (
    ToolContext,
    ToolError,
    ToolExecutionResult,
    ToolKind,
    ToolRequest,
    ToolSpec,
)
from app.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

AuditSink = Callable[[AuditEntry], None]


class ToolExecutor:
    """Validates, authorizes and runs tool requests."""

    def __init__(self, context: ToolContext, audit_sink: AuditSink | None = None) -> None:
        self._ctx = context
        self._audit = audit_sink

    @property
    def registry(self) -> ToolRegistry:
        return self._ctx.registry

    def execute(self, request: ToolRequest) -> ToolExecutionResult:
        result = self._execute(request)
        self._record(request, result)
        return result

    # ---------------------------------------------------------------- pipeline
    def _execute(self, request: ToolRequest) -> ToolExecutionResult:
        spec = self.registry.get(request.tool_name)
        if spec is None:
            return self._reject(request, None, "invalid", "unknown_tool",
                                f"tool '{request.tool_name}' is not registered")

        try:
            args = spec.input_model.model_validate(request.arguments)
        except ValidationError as exc:
            problems = "; ".join(f"{'.'.join(map(str, e['loc'])) or 'arguments'}: {e['msg']}"
                                 for e in exc.errors())
            return self._reject(request, spec, "invalid", "invalid_arguments", problems)

        if not self.registry.is_permitted(request.requested_by, spec.name):
            return self._reject(request, spec, "denied", "permission_denied",
                                f"{request.requested_by.value} may not use '{spec.name}'")

        if spec.kind == ToolKind.ACTION:
            denial = self._check_approval(request, spec)
            if denial:
                return self._reject(request, spec, "denied", *denial)

        try:
            output = spec.handler(self._ctx, args)
        except ToolError as exc:
            return self._reject(request, spec, "failed", exc.code, str(exc))
        except Exception:  # never leak internals to the caller
            logger.exception("tool '%s' crashed", spec.name)
            return self._reject(request, spec, "failed", "execution_error",
                                f"tool '{spec.name}' failed")
        return ToolExecutionResult(
            request_id=request.request_id, tool_name=spec.name, kind=spec.kind,
            requested_by=request.requested_by, incident_id=request.incident_id,
            outcome="succeeded", output=output)

    def _check_approval(self, request: ToolRequest, spec: ToolSpec) -> tuple[str, str] | None:
        """None if the action may run, else (error_code, message)."""
        if request.is_human:
            return None  # an analyst invoking the action directly *is* the human decision
        if not self.registry.agent_actions_enabled:
            return ("agent_actions_disabled",
                    "agents may not execute actions in this phase; an analyst must run it")
        grant = request.approval
        if grant is None or grant.status != ApprovalStatus.APPROVED:
            return ("approval_required", f"'{spec.name}' requires an approved human decision")
        if grant.tool_name != spec.name or grant.incident_id != request.incident_id:
            return ("approval_mismatch", "the approval does not cover this action/incident")
        return None

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _reject(request: ToolRequest, spec: ToolSpec | None, outcome: str, code: str,
                message: str) -> ToolExecutionResult:
        logger.warning("tool request %s (%s by %s) %s: %s", request.request_id,
                       request.tool_name, request.requested_by.value, code, message)
        return ToolExecutionResult(
            request_id=request.request_id, tool_name=request.tool_name,
            kind=spec.kind if spec else None, requested_by=request.requested_by,
            incident_id=request.incident_id, outcome=outcome,  # type: ignore[arg-type]
            error_code=code, error=message)

    def _record(self, request: ToolRequest, result: ToolExecutionResult) -> None:
        if self._audit is None:
            return
        # Reads are logged only when they fail; every action attempt is always logged.
        if result.kind == ToolKind.READ and result.ok:
            return
        entry = AuditEntry(
            incident_id=request.incident_id,
            actor=request.requested_by,
            action=f"tool:{request.tool_name}",
            decision=result.outcome,
            result=result.error or "completed",
            reasoning=request.reason,
            tool_name=request.tool_name,
            details={"request_id": request.request_id, "arguments": request.arguments,
                     "error_code": result.error_code,
                     "approval_id": request.approval.approval_id if request.approval else None,
                     "approved_by": request.approval.decided_by if request.approval
                     else (HumanActor.ANALYST.value if request.is_human else None)},
        )
        try:
            self._audit(entry)
        except Exception:
            logger.exception("could not write audit entry for %s", request.request_id)
