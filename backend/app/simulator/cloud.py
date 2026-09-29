"""In-memory simulated cloud (IAM, EC2, S3).

The methods here stand in for cloud API calls. They only change Python objects;
no real AWS API is ever called.
"""

import logging
import secrets
from threading import RLock
from typing import Any, Callable

from app.simulator.resources import (
    ActionResult,
    EC2Instance,
    IAMAccessKey,
    IAMUser,
    S3Bucket,
)

logger = logging.getLogger(__name__)


class ResourceNotFoundError(LookupError):
    """Raised when a user, instance or bucket does not exist."""


def _new_key_id() -> str:
    """Make a fake access key ID that looks like an AWS one (simulation only)."""
    return "AKIASIM" + secrets.token_hex(6).upper()


class CloudSimulator:
    """Holds and mutates the simulated cloud state.

    The state is encapsulated in this object (no module-level globals). A lock
    makes it safe to share between FastAPI worker threads.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._users: dict[str, IAMUser] = {}
        self._instances: dict[str, EC2Instance] = {}
        self._buckets: dict[str, S3Bucket] = {}
        self.reset()

    # ------------------------------------------------------------------ setup
    def reset(self) -> None:
        """Restore the initial cloud state. Database history is NOT touched."""
        with self._lock:
            self._users = {
                name: IAMUser(
                    name=name,
                    role="developer",
                    admin=False,
                    access_keys=[IAMAccessKey(key_id=_new_key_id(), active=True)],
                )
                for name in ("alice", "bob")
            }
            self._instances = {
                "ec2-001": EC2Instance(instance_id="ec2-001", private_ip="10.0.1.10"),
                "ec2-002": EC2Instance(instance_id="ec2-002", private_ip="10.0.1.11"),
            }
            self._buckets = {
                "company-data": S3Bucket(name="company-data", public_access=False),
                "public-assets": S3Bucket(name="public-assets", public_access=True),
            }
        logger.info("cloud state reset to initial state")

    # ------------------------------------------------------------------ reads
    def get_cloud_state(self) -> dict[str, Any]:
        """Return a JSON-friendly snapshot of the whole cloud."""
        with self._lock:
            return {
                "iam_users": {n: u.model_dump(mode="json") for n, u in self._users.items()},
                "ec2_instances": {
                    i: inst.model_dump(mode="json") for i, inst in self._instances.items()
                },
                "s3_buckets": {n: b.model_dump(mode="json") for n, b in self._buckets.items()},
            }

    def get_user(self, username: str) -> IAMUser:
        """Return a user or raise ResourceNotFoundError."""
        return self._lookup(self._users, username, "IAM user")

    def get_instance(self, instance_id: str) -> EC2Instance:
        """Return an EC2 instance or raise ResourceNotFoundError."""
        return self._lookup(self._instances, instance_id, "EC2 instance")

    def get_bucket(self, name: str) -> S3Bucket:
        """Return an S3 bucket or raise ResourceNotFoundError."""
        return self._lookup(self._buckets, name, "S3 bucket")

    # ------------------------------------------------------------- IAM actions
    def disable_access_key(self, username: str) -> ActionResult:
        """Deactivate all access keys of a user."""
        return self._set_keys_active(username, False, "disable_access_key")

    def enable_access_key(self, username: str) -> ActionResult:
        """Activate all access keys of a user."""
        return self._set_keys_active(username, True, "enable_access_key")

    def create_access_key(self, username: str) -> ActionResult:
        """Create a new active access key for a user."""
        user = self.get_user(username)
        return self._change(
            user, "IAMUser", username, "create_access_key",
            lambda: user.access_keys.append(IAMAccessKey(key_id=_new_key_id())),
            lambda: {"access_key_count": len(user.access_keys),
                     "newest_key_id": user.access_keys[-1].key_id if user.access_keys else None},
        )

    def record_access_key_use(self, username: str, source_ip: str) -> ActionResult:
        """Record that the user's newest active key was used from an IP."""
        user = self.get_user(username)

        def apply() -> None:
            active = [k for k in user.access_keys if k.active]
            if active:
                active[-1].last_used_ip = source_ip

        return self._change(
            user, "IAMUser", username, "use_access_key", apply,
            lambda: {"last_used_ips": [k.last_used_ip for k in user.access_keys]},
        )

    def make_user_admin(self, username: str) -> ActionResult:
        """Grant admin privileges to a user."""
        return self._set_admin(username, True, "make_user_admin")

    def remove_admin_privileges(self, username: str) -> ActionResult:
        """Revoke admin privileges from a user."""
        return self._set_admin(username, False, "remove_admin_privileges")

    # -------------------------------------------------------------- EC2 actions
    def isolate_instance(self, instance_id: str) -> ActionResult:
        """Isolate an instance (simulated quarantine security group)."""
        return self._set_instance_status(instance_id, "isolated", "isolate_instance")

    def restore_instance(self, instance_id: str) -> ActionResult:
        """Return an isolated instance to normal operation."""
        return self._set_instance_status(instance_id, "running", "restore_instance")

    def set_instance_role(self, instance_id: str, role: str) -> ActionResult:
        """Change the IAM role attached to an instance."""
        instance = self.get_instance(instance_id)
        return self._change(
            instance, "EC2Instance", instance_id, "set_instance_role",
            lambda: setattr(instance, "iam_role", role),
            lambda: {"iam_role": instance.iam_role},
        )

    # --------------------------------------------------------------- S3 actions
    def make_bucket_public(self, name: str) -> ActionResult:
        """Make a bucket publicly accessible."""
        return self._set_bucket_public(name, True, "make_bucket_public")

    def make_bucket_private(self, name: str) -> ActionResult:
        """Block public access to a bucket."""
        return self._set_bucket_public(name, False, "make_bucket_private")

    # ---------------------------------------------------------------- internals
    @staticmethod
    def _lookup(store: dict[str, Any], key: str, kind: str) -> Any:
        try:
            return store[key]
        except KeyError:
            raise ResourceNotFoundError(f"{kind} '{key}' not found") from None

    def _change(
        self,
        model: Any,
        resource_type: str,
        resource: str,
        action: str,
        apply: Callable[[], None],
        snapshot: Callable[[], dict[str, Any]],
    ) -> ActionResult:
        """Run `apply` and report old/new state as measured by `snapshot`."""
        with self._lock:
            old_state = snapshot()
            apply()
            new_state = snapshot()
        logger.info("cloud state changed: %s on %s %s", action, resource_type, resource)
        return ActionResult(
            success=True, resource=resource, resource_type=resource_type,
            action=action, old_state=old_state, new_state=new_state,
        )

    def _set_keys_active(self, username: str, active: bool, action: str) -> ActionResult:
        user = self.get_user(username)

        def apply() -> None:
            for key in user.access_keys:
                key.active = active

        return self._change(user, "IAMUser", username, action, apply,
                            lambda: {"access_key_active": user.access_key_active})

    def _set_admin(self, username: str, admin: bool, action: str) -> ActionResult:
        user = self.get_user(username)
        return self._change(user, "IAMUser", username, action,
                            lambda: setattr(user, "admin", admin),
                            lambda: {"admin": user.admin})

    def _set_instance_status(self, instance_id: str, status: str, action: str) -> ActionResult:
        instance = self.get_instance(instance_id)
        return self._change(instance, "EC2Instance", instance_id, action,
                            lambda: setattr(instance, "status", status),
                            lambda: {"status": instance.status})

    def _set_bucket_public(self, name: str, public: bool, action: str) -> ActionResult:
        bucket = self.get_bucket(name)
        return self._change(bucket, "S3Bucket", name, action,
                            lambda: setattr(bucket, "public_access", public),
                            lambda: {"public_access": bucket.public_access})
