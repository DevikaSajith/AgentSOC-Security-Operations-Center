"""Deterministic entity extraction and a lightweight in-memory relationship view.

Only relationships the evidence directly shows are 'confirmed'. A relationship the data
cannot prove (e.g. that activity from two different IPs was the same actor) is added as
'possible' so the uncertainty is explicit rather than hidden.
"""

from app.agents.investigator.evidence import EvidenceCatalog
from app.domain.investigation import Certainty, Entity, Relationship

UNSPECIFIED_IP = "0.0.0.0"
RESOURCE_ENTITY_TYPE = {"S3Bucket": "bucket", "EC2Instance": "instance", "Secret": "secret",
                        "IAMUser": "iam_user", "SecurityGroup": "security_group"}
LOGIN_EVENTS = {"Login", "ConsoleLogin"}


class _Builder:
    def __init__(self) -> None:
        self.entities: dict[tuple[str, str], Entity] = {}
        self.relationships: dict[tuple[str, str, str], Relationship] = {}

    def entity(self, type_: str, value: str, evidence_id: str | None = None, **attributes) -> Entity:
        key = (type_, value)
        if key not in self.entities:
            self.entities[key] = Entity(entity_id=f"EN{len(self.entities) + 1}", type=type_, value=value)
        found = self.entities[key]
        if evidence_id and evidence_id not in found.evidence_ids:
            found.evidence_ids.append(evidence_id)
        found.attributes.update({k: v for k, v in attributes.items() if v is not None})
        return found

    def relate(self, source: Entity, relation: str, target: Entity, evidence_id: str | None,
               certainty: Certainty = Certainty.CONFIRMED) -> None:
        key = (source.entity_id, relation, target.entity_id)
        if key not in self.relationships:
            self.relationships[key] = Relationship(source=source.entity_id, relation=relation,
                                                   target=target.entity_id, certainty=certainty)
        rel = self.relationships[key]
        if evidence_id and evidence_id not in rel.evidence_ids:
            rel.evidence_ids.append(evidence_id)


def build_entities(catalog: EvidenceCatalog) -> tuple[list[Entity], list[Relationship]]:
    b = _Builder()
    principal_ips: dict[str, set[str]] = {}
    for e in catalog.events:
        ev = e.evidence_id
        account = b.entity("account", e.account_id, ev)
        region = b.entity("region", e.region, ev)
        actor = b.entity("principal", e.principal, ev) if e.principal != "unknown" else None
        target = None
        if e.resource_id and e.resource_id != "*":
            target = b.entity(RESOURCE_ENTITY_TYPE.get(e.resource_type, "resource"),
                              f"{e.resource_type}/{e.resource_id}", ev)
            b.relate(target, "in_account", account, ev)
            b.relate(target, "in_region", region, ev)
        if e.source_ip != UNSPECIFIED_IP:
            # per the Monitor's trusted_networks rule (config/monitor_rules.yaml)
            ip = b.entity("source_ip", e.source_ip, ev, trusted="untrusted_source_ip" not in e.indicators)
            if actor:
                b.relate(actor, "authenticated_from" if e.event_type in LOGIN_EVENTS else "used_source_ip",
                         ip, ev)
                principal_ips.setdefault(actor.entity_id, set()).add(ip.entity_id)
            if target:
                b.relate(ip, "originated_activity_on", target, ev)
        if actor and target and target.value != f"IAMUser/{e.principal}":
            b.relate(actor, "acted_on", target, ev)
        if actor and e.event_type == "CreateAccessKey":
            key = b.entity("access_key", f"new access key of {e.principal} (id redacted)", ev)
            b.relate(actor, "created", key, ev)
        destination = e.details.get("dstaddr")
        if destination and target:
            dst = b.entity("destination_ip", str(destination), ev, port=e.details.get("dstport"),
                           bytes=e.details.get("bytes"))
            b.relate(target, "connected_to", dst, ev)
    # Same principal seen from several IPs: the data shows the identity, not the person.
    for actor_id, ips in principal_ips.items():
        ordered = sorted(ips)
        for a, c in zip(ordered, ordered[1:]):
            source = next(x for x in b.entities.values() if x.entity_id == a)
            target = next(x for x in b.entities.values() if x.entity_id == c)
            b.relate(source, "same_actor_as", target, None, certainty=Certainty.POSSIBLE)
    for item in catalog.items.values():  # current-state evidence attached to its entity
        if item.type == "iam":
            b.entity("principal", item.entity, item.evidence_id)
        elif item.type == "resource":
            resource_type = item.entity.split("/", 1)[0]
            b.entity(RESOURCE_ENTITY_TYPE.get(resource_type, "resource"), item.entity, item.evidence_id)
    return list(b.entities.values()), list(b.relationships.values())
