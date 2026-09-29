"""Read-only views of the simulated cloud for the API.

The posture labels are deterministic facts about the current simulated state (a bucket
is public, an instance is isolated, ...). They are not threat assessments.
"""

from typing import Any, Literal

from pydantic import BaseModel

from app.simulator.cloud import CloudSimulator

Posture = Literal["Healthy", "At risk", "Exposed", "Isolated"]
BASELINE_INSTANCE_ROLE = "ec2-basic-role"


class CloudResourceView(BaseModel):
    """One resource in the flat inventory list."""

    category: Literal["IAM", "EC2", "S3"]
    resource_type: str
    resource_id: str
    name: str
    detail: str
    status: Posture
    reasons: list[str]


def _iam(name: str, user: dict[str, Any]) -> CloudResourceView:
    keys = user["access_keys"]
    active = sum(1 for k in keys if k["active"])
    reasons = []
    if user["admin"]:
        reasons.append("user has admin privileges")
    return CloudResourceView(
        category="IAM", resource_type="IAMUser", resource_id=name, name=name,
        detail=f"User · role {user['role']} · {active}/{len(keys)} access keys active",
        status="At risk" if reasons else "Healthy", reasons=reasons)


def _ec2(instance_id: str, inst: dict[str, Any]) -> CloudResourceView:
    reasons = []
    if inst["iam_role"] != BASELINE_INSTANCE_ROLE:
        reasons.append(f"instance role changed to {inst['iam_role']}")
    if inst["status"] == "isolated":
        status: Posture = "Isolated"
    else:
        status = "At risk" if reasons else "Healthy"
    return CloudResourceView(
        category="EC2", resource_type="EC2Instance", resource_id=instance_id, name=instance_id,
        detail=f"Instance · {inst['status']} · {inst['private_ip']} · {inst['iam_role']}",
        status=status, reasons=reasons)


def _s3(name: str, bucket: dict[str, Any]) -> CloudResourceView:
    public = bucket["public_access"]
    return CloudResourceView(
        category="S3", resource_type="S3Bucket", resource_id=name, name=name,
        detail=f"Bucket · {'public' if public else 'private'} access",
        status="Exposed" if public else "Healthy",
        reasons=["bucket allows public access"] if public else [])


def cloud_overview(cloud: CloudSimulator) -> dict[str, Any]:
    """Raw simulator state plus a flat, posture-labelled resource list and counts."""
    state = cloud.get_cloud_state()
    resources = (
        [_iam(n, u) for n, u in state["iam_users"].items()]
        + [_ec2(i, inst) for i, inst in state["ec2_instances"].items()]
        + [_s3(n, b) for n, b in state["s3_buckets"].items()]
    )
    summary: dict[str, int] = {"total": len(resources)}
    for posture in ("Healthy", "At risk", "Exposed", "Isolated"):
        summary[posture.lower().replace(" ", "_")] = sum(
            1 for r in resources if r.status == posture)
    return {
        "simulated": True,
        "state": state,
        "resources": [r.model_dump() for r in resources],
        "summary": summary,
    }
