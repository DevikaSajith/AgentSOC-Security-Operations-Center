"""The Monitor Agent (deterministic; no LLM).

    incoming events -> validate + normalize -> fingerprint -> deduplicate -> correlate
      -> enrich -> incident decision -> create/update IncidentState -> audit -> AgentResult

It is READ-ONLY toward the cloud: its only tool use is `get_resource` (enrichment), made
through the ToolExecutor as the Monitor Agent, so its permissions are enforced there.
It never triages, investigates, checks compliance or remediates, and it calls no other agent.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable
from uuid import uuid4

from app.agents.base import BaseAgent
from app.agents.monitor.config import MonitorConfig
from app.agents.monitor.correlation import correlate
from app.agents.monitor.decision import decide
from app.agents.monitor.dedup import DedupResult, deduplicate
from app.agents.monitor.enrichment import Enricher
from app.agents.monitor.fingerprint import fingerprint
from app.agents.monitor.incidents import build_incident, matches_open_incident, merge_into
from app.agents.monitor.models import (
    EventGroup,
    GroupReport,
    IncidentDecision,
    MonitorRunReport,
    MonitorRunRequest,
    NormalizedEvent,
    RejectedEvent,
)
from app.agents.monitor.normalizer import EventNormalizer, EventRejection, rejection_record
from app.database.connection import Database
from app.database.models import MonitorLedgerRecord, MonitorRunRecord
from app.domain.agent_result import AgentAction, AgentResult
from app.domain.enums import AgentName, AgentRunStatus
from app.domain.events import SecurityEvent, utcnow
from app.domain.incident import AuditEntry, Evidence, IncidentState
from app.services.event_service import EventService
from app.services.incident_service import IncidentService
from app.services.monitor_ledger import MonitorLedgerService
from app.tools.base import ToolRequest
from app.tools.executor import ToolExecutor

logger = logging.getLogger(__name__)

AuditSink = Callable[[AuditEntry], None]


@dataclass
class _Touched:
    """An incident created or updated by this run, with what produced it."""

    incident: IncidentState
    group: EventGroup
    decision: IncidentDecision
    created: bool


@dataclass
class _RunState:
    run_id: str
    now: datetime
    normalized: list[NormalizedEvent] = field(default_factory=list)
    rejected: list[RejectedEvent] = field(default_factory=list)
    dedup: DedupResult = field(default_factory=DedupResult)
    groups: list[tuple[EventGroup, IncidentDecision]] = field(default_factory=list)
    touched: dict[str, _Touched] = field(default_factory=dict)  # group_id -> incident
    reports: list[GroupReport] = field(default_factory=list)
    rejected_stored: list[SecurityEvent] = field(default_factory=list)  # ledgered as 'rejected'


class MonitorAgent(BaseAgent[MonitorRunRequest, MonitorRunReport]):
    name = AgentName.MONITOR

    def __init__(self, database: Database, config: MonitorConfig, tools: ToolExecutor | None,
                 audit_sink: AuditSink, clock: Callable[[], datetime] = utcnow) -> None:
        self._db = database
        self._config = config
        self._tools = tools
        self._audit = audit_sink
        self._clock = clock
        self._normalizer = EventNormalizer(config, clock)

    # ------------------------------------------------------------------ entry
    def run(self, request: MonitorRunRequest) -> MonitorRunReport:
        state = _RunState(run_id=f"MON-{uuid4().hex[:10].upper()}", now=self._clock())
        try:
            self._collect(state, request)
            self._deduplicate(state)
            self._store_submitted(state)
            self._correlate_and_decide(state)
            self._apply_incidents(state)
            result = self._run_result(state)
        except Exception as exc:  # the agent reports failures; it never crashes its caller
            logger.exception("monitor run %s failed", state.run_id)
            result = AgentResult(
                agent_name=self.name, status=AgentRunStatus.FAILED, outcome="run_failed",
                confidence=0.0, reasoning_summary="The Monitor Agent run failed unexpectedly.",
                errors=[f"internal_error:{type(exc).__name__}"])
        self._record(state, result)
        return self._report(state, result)

    # ------------------------------------------------------ stage 1-2: collect
    def _collect(self, state: _RunState, request: MonitorRunRequest) -> None:
        if request.events is not None:
            for index, raw in enumerate(request.events):
                try:
                    state.normalized.append(self._normalizer.normalize_raw(raw))
                except EventRejection as exc:
                    state.rejected.append(rejection_record(exc, index))
            return
        with self._db.session() as session:
            if request.event_ids is not None:
                stored = EventService(session).get_events_by_ids(request.event_ids)
                found = {e.event_id for e in stored}
                state.rejected.extend(
                    RejectedEvent(event_id=i, reason="event_not_found")
                    for i in dict.fromkeys(request.event_ids) if i not in found)
            else:
                since = (state.now - timedelta(minutes=request.time_window_minutes)
                         if request.time_window_minutes else None)
                stored = MonitorLedgerService(session).unprocessed_events(since, request.limit)
        for event in stored:
            try:
                state.normalized.append(self._normalizer.normalize_stored(event))
            except EventRejection as exc:
                state.rejected.append(rejection_record(exc))
                state.rejected_stored.append(event)

    # ---------------------------------------------------- stage 3-4: dedup
    def _deduplicate(self, state: _RunState) -> None:
        with self._db.session() as session:
            ledger = MonitorLedgerService(session)
            processed = ledger.processed_event_ids(n.event.event_id for n in state.normalized)
            owners = ledger.fingerprint_owners(n.fingerprint for n in state.normalized)
        state.dedup = deduplicate(state.normalized, processed, owners)

    def _store_submitted(self, state: _RunState) -> None:
        """Persist accepted, non-duplicate submitted events so they appear in the event store."""
        new = [n for n in state.dedup.unique if not n.stored]
        if not new:
            return
        with self._db.session() as session:
            service = EventService(session)
            existing = {e.event_id for e in service.get_events_by_ids([n.event.event_id for n in new])}
            service.save_events([n.event for n in new if n.event.event_id not in existing])

    # ------------------------------------------- stage 5-7: correlate/enrich/decide
    def _correlate_and_decide(self, state: _RunState) -> None:
        enricher = Enricher(self._config, self._lookup_resource if self._tools else None)
        for items in correlate(state.dedup.unique, self._config.correlation.window_seconds):
            group = enricher.build_group(items)
            state.groups.append((group, decide(group, self._config)))

    def _lookup_resource(self, resource_type: str, resource_id: str) -> dict[str, Any] | None:
        assert self._tools is not None
        result = self._tools.execute(ToolRequest(
            tool_name="get_resource", requested_by=self.name, reason="monitor enrichment",
            arguments={"resource_type": resource_type, "resource_id": resource_id}))
        return result.output.get("state") if result.ok else None

    # ------------------------------------------------- stage 8: incidents
    def _apply_incidents(self, state: _RunState) -> None:
        merge_since = state.now - timedelta(minutes=self._config.incident.merge_window_minutes)
        for group, decision in state.groups:
            incident_id = None
            outcome = "no_incident"
            if decision.create_incident:
                with self._db.session() as session:
                    service = IncidentService(session)
                    candidates = service.list_open_updated_since(
                        merge_since, self._config.incident.closed_statuses)
                    match = next((i for i in candidates if matches_open_incident(
                        i, group, decision, self._config, state.now)), None)
                    created = match is None
                    incident = (build_incident(group, decision, state.now) if created
                                else merge_into(match, group, decision, self._config, state.now))
                    entry = AuditEntry(
                        timestamp=state.now, incident_id=incident.incident_id, actor=self.name,
                        action="monitor.create_incident" if created else "monitor.update_incident",
                        decision="incident_created" if created else "incident_updated",
                        result=f"{len(group.events)} event(s) from group {group.group_id}",
                        reasoning=decision.reason, confidence=decision.confidence,
                        details={"run_id": state.run_id, "group_id": group.group_id,
                                 "event_ids": group.event_ids, "rules_matched": decision.rules_matched,
                                 "severity": decision.severity.value,
                                 "category": decision.category.value})
                    incident = service.save(incident.model_copy(
                        update={"audit_log": incident.audit_log + [entry]}))
                self._audit(entry)
                state.touched[group.group_id] = _Touched(incident, group, decision, created)
                incident_id = incident.incident_id
                outcome = "incident_created" if created else "incident_updated"
            state.reports.append(GroupReport(
                group_id=group.group_id, event_ids=group.event_ids, principal_id=group.principal_id,
                source_ips=sorted({e.event.source_ip for e in group.events}),
                indicators=decision.indicators, decision=outcome,
                rules_matched=decision.rules_matched, incident_id=incident_id,
                confidence=decision.confidence))

    # ------------------------------------------------------ stage 9: results
    @staticmethod
    def _new_evidence(touched: _Touched, now: datetime) -> list[Evidence]:
        """The evidence this run added to the incident (same objects/IDs as persisted)."""
        return [e for e in touched.incident.evidence if e.collected_at == now]

    def _incident_result(self, touched: _Touched, now: datetime) -> AgentResult:
        incident, decision = touched.incident, touched.decision
        return AgentResult(
            agent_name=self.name, incident_id=incident.incident_id, status=AgentRunStatus.SUCCESS,
            outcome="incident_created" if touched.created else "incident_updated",
            confidence=decision.confidence, reasoning_summary=decision.reason,
            findings=[f"rule:{r}" for r in decision.rules_matched]
            + [f"indicator:{i}" for i in decision.indicators]
            + [f"initial_severity:{decision.severity.value}", f"initial_priority:{decision.priority.value}",
               f"category:{decision.category.value}"],
            evidence=self._new_evidence(touched, now),
            actions=[AgentAction(action="create_incident" if touched.created else "update_incident",
                                 target=incident.incident_id,
                                 details={"group_id": touched.group.group_id,
                                          "event_ids": touched.group.event_ids})],
            recommendations=[f"forward_to_triage:{incident.incident_id}"],
            timestamp=now)

    def _run_result(self, state: _RunState) -> AgentResult:
        touched = list(state.touched.values())
        created = [t.incident.incident_id for t in touched if t.created]
        updated = [t.incident.incident_id for t in touched if not t.created]
        received = len(state.normalized) + len(state.rejected)
        if received == 0:
            status, outcome = AgentRunStatus.SKIPPED, "no_events"
        elif not state.normalized:
            status, outcome = AgentRunStatus.FAILED, "all_events_rejected"
        else:
            status = AgentRunStatus.PARTIAL if state.rejected else AgentRunStatus.SUCCESS
            if created and updated:
                outcome = "incidents_created_and_updated"
            elif created:
                outcome = "incident_created"
            elif updated:
                outcome = "incident_updated"
            elif not state.dedup.unique:
                outcome = "no_new_events"
            else:
                outcome = "no_incident"
        incidents = created + updated
        unique = len(state.dedup.unique)
        summary = (f"Processed {unique} new event(s) in {len(state.groups)} correlated group(s): "
                   f"{len(created)} incident(s) created, {len(updated)} updated; "
                   f"{len(state.rejected)} rejected, {len(state.dedup.duplicates)} duplicate(s), "
                   f"{len(state.dedup.already_processed)} already processed.")
        return AgentResult(
            agent_name=self.name, status=status, outcome=outcome,
            incident_id=incidents[0] if len(incidents) == 1 else None,
            confidence=max((d.confidence for _, d in state.groups), default=0.0),
            reasoning_summary=summary,
            findings=[f"group:{r.group_id}:{r.decision}:{','.join(r.indicators) or 'no_indicators'}"
                      for r in state.reports]
            + [f"duplicate:{d.event_id}:of:{d.duplicate_of}" for d in state.dedup.duplicates]
            + [f"rejected:{r.reason}:{r.event_id or r.index}" for r in state.rejected],
            evidence=[e for t in touched for e in self._new_evidence(t, state.now) if e.kind == "event"],
            actions=[AgentAction(action="create_incident" if t.created else "update_incident",
                                 target=t.incident.incident_id,
                                 details={"group_id": t.group.group_id}) for t in touched]
            + [AgentAction(action="reject_event", target=r.event_id,
                           details={"index": r.index, "reason": r.reason}) for r in state.rejected],
            recommendations=[f"forward_to_triage:{i}" for i in incidents],
            errors=[f"{r.reason}:{r.event_id or r.index}" for r in state.rejected]
            if status == AgentRunStatus.FAILED else [],
            timestamp=state.now)

    # -------------------------------------------------------- audit + ledger
    def _record(self, state: _RunState, result: AgentResult) -> None:
        for rejected in state.rejected:
            self._audit(AuditEntry(
                timestamp=state.now, actor=self.name, action="monitor.reject_event",
                decision="rejected", result=rejected.reason, reasoning=rejected.detail,
                details={"run_id": state.run_id, "event_id": rejected.event_id,
                         "index": rejected.index}))
        processed_ids = [n.event.event_id for n in state.dedup.unique]
        self._audit(AuditEntry(
            timestamp=state.now, actor=self.name, action="monitor.run",
            decision=result.status.value, result=result.outcome,
            reasoning=result.reasoning_summary, confidence=result.confidence,
            incident_id=result.incident_id,
            details={"run_id": state.run_id, "event_ids_processed": processed_ids,
                     "events_accepted": len(processed_ids),
                     "events_rejected": len(state.rejected),
                     "duplicates": [d.event_id for d in state.dedup.duplicates],
                     "already_processed": len(state.dedup.already_processed),
                     "correlated_groups": [{"group_id": r.group_id, "event_ids": r.event_ids,
                                            "decision": r.decision} for r in state.reports],
                     "incidents_created": [t.incident.incident_id for t in state.touched.values() if t.created],
                     "incidents_updated": [t.incident.incident_id for t in state.touched.values() if not t.created],
                     "errors": result.errors}))
        try:
            with self._db.session() as session:
                MonitorLedgerService(session).record_run(self._ledger_rows(state), MonitorRunRecord(
                    run_id=state.run_id, started_at=state.now, finished_at=self._clock(),
                    status=result.status.value, outcome=result.outcome,
                    events_processed=len(state.dedup.unique), events_rejected=len(state.rejected),
                    duplicates=len(state.dedup.duplicates),
                    incidents_created=sum(1 for t in state.touched.values() if t.created),
                    incidents_updated=sum(1 for t in state.touched.values() if not t.created),
                    result=result.model_dump(mode="json", exclude={"evidence"})))
        except Exception:
            logger.exception("could not record monitor run %s", state.run_id)

    def _ledger_rows(self, state: _RunState) -> list[MonitorLedgerRecord]:
        rows: dict[str, MonitorLedgerRecord] = {}
        incident_by_event = {event_id: (t.incident.incident_id, t.created)
                             for t in state.touched.values() for event_id in t.group.event_ids}
        for item in state.dedup.unique:
            event_id = item.event.event_id
            incident = incident_by_event.get(event_id)
            outcome = ("no_incident" if incident is None
                       else "incident_created" if incident[1] else "incident_updated")
            rows[event_id] = MonitorLedgerRecord(
                event_id=event_id, fingerprint=item.fingerprint, run_id=state.run_id,
                outcome=outcome, incident_id=incident[0] if incident else None)
        fingerprints = {n.event.event_id: n.fingerprint for n in state.normalized}
        for dup in state.dedup.duplicates:
            if dup.event_id not in rows:
                rows[dup.event_id] = MonitorLedgerRecord(
                    event_id=dup.event_id, fingerprint=fingerprints[dup.event_id],
                    run_id=state.run_id, outcome="duplicate", duplicate_of=dup.duplicate_of)
        for event in state.rejected_stored:
            rows.setdefault(event.event_id, MonitorLedgerRecord(
                event_id=event.event_id, fingerprint=fingerprint(event), run_id=state.run_id,
                outcome="rejected"))
        return list(rows.values())

    def _report(self, state: _RunState, result: AgentResult) -> MonitorRunReport:
        touched = list(state.touched.values())
        return MonitorRunReport(
            run_id=state.run_id, processed_events=len(state.dedup.unique),
            accepted_event_ids=[n.event.event_id for n in state.dedup.unique],
            rejected_events=state.rejected, duplicates=state.dedup.duplicates,
            already_processed=state.dedup.already_processed, correlated_groups=state.reports,
            incidents_created=[t.incident.incident_id for t in touched if t.created],
            incidents_updated=[t.incident.incident_id for t in touched if not t.created],
            agent_result=result,
            incident_results=[self._incident_result(t, state.now) for t in touched])
