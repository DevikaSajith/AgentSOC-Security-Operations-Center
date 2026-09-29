"""Pydantic models for simulated cloud resources.

Everything here is an in-memory SIMULATION. Nothing talks to real AWS.
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, computed_field

from app.domain.events import utcnow

__all__ = ["ActionResult", "EC2Instance", "IAMAccessKey", "IAMUser", "S3Bucket", "utcnow"]


class IAMAccessKey(BaseModel):
    """An access key belonging to an IAM user."""

    id: UUID = Field(default_factory=uuid4)
    key_id: str
    active: bool = True
    last_used_ip: str | None = None


class IAMUser(BaseModel):
    """A simulated IAM user with a role and access keys."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    role: str
    admin: bool = False
    access_keys: list[IAMAccessKey] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def access_key_active(self) -> bool:
        """True if at least one access key is active."""
        return any(key.active for key in self.access_keys)


class EC2Instance(BaseModel):
    """A simulated EC2 instance."""

    id: UUID = Field(default_factory=uuid4)
    instance_id: str
    status: Literal["running", "isolated"] = "running"
    private_ip: str
    iam_role: str = "ec2-basic-role"


class S3Bucket(BaseModel):
    """A simulated S3 bucket."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    public_access: bool = False


class ActionResult(BaseModel):
    """Result of a simulated state-changing cloud API call."""

    success: bool
    resource: str
    resource_type: str
    action: str
    old_state: dict[str, Any]
    new_state: dict[str, Any]
    timestamp: datetime = Field(default_factory=utcnow)
