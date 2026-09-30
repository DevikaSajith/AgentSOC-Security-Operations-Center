"""Feedback & Learning models (Phase 8). A deterministic backend service, NOT an LLM agent.

A LearningRecord is a compact, structured summary of what happened to one incident's response: what was
proposed, what verification found, how the outcome is classified, why it failed (deterministic rules only),
what is recommended next, and what an analyst said. It never contains prompts, raw model output, reasoning
traces, credentials, access keys or secrets - only enums, ids, statuses and redacted state summaries.
The Feedback Engine can only RECOMMEND: any action still needs human approval, the kill switch and the ToolExecutor.
"""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain.events import utcnow


class FeedbackType(str, Enum):
    SUCCESSFUL_RESPONSE = "successful_response"
    FAILED_RESPONSE = "failed_response"
    PARTIAL_RESPONSE = "partial_response"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    REGRESSION_DETECTED = "regression_detected"
    RETRY_REQUESTED = "retry_requested"


class HumanFeedback(str, Enum):
    CORRECT = "correct"
    INCORRECT = "incorrect"
    PARTIALLY_CORRECT = "partially_correct"
    NEEDS_REVIEW = "needs_review"


# A human verdict overrides the automatically inferred feedback type.
HUMAN_TO_FEEDBACK = {
    HumanFeedback.CORRECT: FeedbackType.SUCCESSFUL_RESPONSE,
    HumanFeedback.INCORRECT: FeedbackType.FAILED_RESPONSE,
    HumanFeedback.PARTIALLY_CORRECT: FeedbackType.PARTIAL_RESPONSE,
    HumanFeedback.NEEDS_REVIEW: FeedbackType.INSUFFICIENT_EVIDENCE,
}


class FailureReason(str, Enum):
    WRONG_TARGET = "wrong_target"
    WRONG_ACTION = "wrong_action"
    EXECUTION_FAILURE = "execution_failure"
    EXPECTED_STATE_NOT_REACHED = "expected_state_not_reached"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    STATE_REGRESSION = "state_regression"
    UNKNOWN = "unknown"


class Recommendation(str, Enum):
    RETRY_SAME_ACTION = "retry_same_action"
    ALTERNATIVE_ACTION = "alternative_action"
    REINVESTIGATE = "reinvestigate"
    REQUEST_HUMAN_REVIEW = "request_human_review"
    KEEP_INCIDENT_OPEN = "keep_incident_open"
    MONITOR_RESOURCE = "monitor_resource"
    NO_FURTHER_ACTION = "no_further_action"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def new_learning_id() -> str:
    return f"LRN-{uuid4().hex[:10].upper()}"


class LearningRecord(_Strict):
    learning_id: str = Field(default_factory=new_learning_id)
    incident_id: str
    timestamp: datetime = Field(default_factory=utcnow)
    incident_category: str
    attack_type: str  # the triage classification if there is one, else the incident's event type
    initial_severity: str
    final_severity: str
    initial_priority: str | None = None
    final_priority: str | None = None
    agent_run_ids: dict[str, str] = Field(default_factory=dict)  # agent -> latest run id (ids only)
    remediation_action: str | None = None
    remediation_target: str | None = None
    verification_run_id: str | None = None
    verification_status: str | None = None
    verification_result: dict[str, Any] = Field(default_factory=dict)  # redacted expected/actual summary
    auto_feedback_type: FeedbackType  # what the engine inferred
    feedback_type: FeedbackType  # effective (a human verdict overrides the inferred one)
    failure_reason: FailureReason | None = None
    recommendation: Recommendation
    human_feedback: HumanFeedback | None = None
    human_comment: str | None = Field(default=None, max_length=500)
    successful: bool
    # retry bookkeeping (feedback_type == retry_requested)
    retry_count: int = 0
    retry_limit: int | None = None
    previous_run_id: str | None = None  # the remediation run the retry follows
    retry_reason: str | None = Field(default=None, max_length=500)
    retry_run_id: str | None = None  # the new remediation planning run (a proposal, never an execution)
    # metadata that is safe to keep
    providers: dict[str, str] = Field(default_factory=dict)  # agent -> "provider/model" (no credentials)
    ml_prediction: str | None = None
    ml_features: dict[str, float] | None = None
    ml_model_version: str | None = None

    @model_validator(mode="after")
    def _consistent(self) -> "LearningRecord":
        if self.human_feedback is None and self.feedback_type != self.auto_feedback_type:
            raise ValueError("without human feedback the effective type equals the inferred type")
        if self.human_feedback is not None and self.feedback_type != HUMAN_TO_FEEDBACK[self.human_feedback]:
            raise ValueError("human feedback must determine the effective feedback type")
        return self

    @property
    def human_corrected(self) -> bool:
        return self.human_feedback is not None and self.feedback_type != self.auto_feedback_type
