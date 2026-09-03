"""Demo orchestrator — runs the full attack-scenario pipeline.

Reuses existing services: EventService, DetectionService, CorrelationService,
InvestigationService, ResponseService, ReportService. Risk, timeline, and
attack stages are computed automatically by the correlation engine.
"""

import time
import uuid
import logging
from datetime import datetime, timezone
from typing import List

from sqlalchemy.orm import Session

from app.ai.demo_provider import DemoInvestigatorProvider
from app.ai.service import InvestigationService
from app.demo.schemas import DemoAttackScenarioResponse, DemoStageResult
from app.demo.scenario import build_attack_scenario_events
from app.reports.service import ReportService
from app.response.service import ResponseService
from app.schemas import EventCreate
from app.services import (
    CorrelationService,
    DetectionService,
    EventService,
)

logger = logging.getLogger(__name__)


class DemoOrchestrator:
    def run(self, db: Session) -> DemoAttackScenarioResponse:
        demo_run_id = str(uuid.uuid4())
        executed_at = datetime.now(timezone.utc)
        stages: List[DemoStageResult] = []
        total_start = time.monotonic()

        events_created = 0
        alerts_created = 0
        rule_detections = 0
        ml_detections = 0
        incident_ids: List[str] = []
        primary_incident_id = None
        risk_score = None
        risk_level = None
        investigation_status = "skipped"
        recommendation_count = 0
        report_generated = False
        attack_stages: List[str] = []

        # Close all existing open incidents to ensure this scenario run
        # creates new incidents instead of merging into existing ones
        _close_open_incidents(db)

        # --- Stage 1: INGEST ---
        stage_start = time.monotonic()
        try:
            event_dicts = build_attack_scenario_events(demo_run_id)
            for ed in event_dicts:
                EventService.create_event(db, EventCreate(**ed))
                events_created += 1
            stages.append(DemoStageResult(
                stage="INGEST",
                status="success",
                duration_ms=_elapsed_ms(stage_start),
                details={"events_created": events_created},
            ))
        except Exception as exc:
            stages.append(DemoStageResult(
                stage="INGEST", status="error",
                duration_ms=_elapsed_ms(stage_start), error=str(exc),
            ))
            return _build_response(
                demo_run_id, executed_at, stages, total_start,
                events_created, alerts_created, rule_detections, ml_detections,
                incident_ids, primary_incident_id, risk_score, risk_level,
                investigation_status, recommendation_count, report_generated,
                attack_stages,
            )

        # --- Stage 2: DETECT ---
        stage_start = time.monotonic()
        try:
            _ensure_rules(db)
            result = DetectionService.process_unprocessed_events_with_stats(db)
            alerts_created = len(result.alerts)
            rule_detections = sum(
                1 for a in result.alerts if a.detection_source == "rule"
            )
            ml_detections = sum(
                1 for a in result.alerts if a.detection_source == "ml"
            )
            # Tag all newly created alerts with the demo run ID for isolation
            new_alert_ids = [a.id for a in result.alerts]
            stages.append(DemoStageResult(
                stage="DETECT",
                status="success",
                duration_ms=_elapsed_ms(stage_start),
                details={
                    "processed_count": result.processed_count,
                    "alerts_created": alerts_created,
                    "rule_detections": rule_detections,
                    "ml_detections": ml_detections,
                    "alert_ids": new_alert_ids,
                },
            ))
        except Exception as exc:
            stages.append(DemoStageResult(
                stage="DETECT", status="error",
                duration_ms=_elapsed_ms(stage_start), error=str(exc),
            ))
            return _build_response(
                demo_run_id, executed_at, stages, total_start,
                events_created, alerts_created, rule_detections, ml_detections,
                incident_ids, primary_incident_id, risk_score, risk_level,
                investigation_status, recommendation_count, report_generated,
                attack_stages,
            )

        # --- Stage 3: CORRELATE ---
        # Only correlate the alerts from THIS scenario run to ensure isolation
        stage_start = time.monotonic()
        try:
            corr_result = CorrelationService.run_with_stats(db, alert_ids=new_alert_ids)
            incident_ids = [i.id for i in corr_result.incidents]
            if corr_result.incidents:
                primary = max(corr_result.incidents, key=lambda i: i.alert_count)
                primary_incident_id = primary.id
                risk_score = primary.risk_score
                risk_level = primary.risk_level
                attack_stages = primary.attack_stages or []
            stages.append(DemoStageResult(
                stage="CORRELATE",
                status="success",
                duration_ms=_elapsed_ms(stage_start),
                details={
                    "incidents_touched": len(corr_result.incidents),
                    "incidents_created": len(corr_result.created_incident_ids),
                    "incident_ids": incident_ids,
                    "primary_incident_id": primary_incident_id,
                },
            ))
        except Exception as exc:
            stages.append(DemoStageResult(
                stage="CORRELATE", status="error",
                duration_ms=_elapsed_ms(stage_start), error=str(exc),
            ))
            return _build_response(
                demo_run_id, executed_at, stages, total_start,
                events_created, alerts_created, rule_detections, ml_detections,
                incident_ids, primary_incident_id, risk_score, risk_level,
                investigation_status, recommendation_count, report_generated,
                attack_stages,
            )

        if not primary_incident_id:
            return _build_response(
                demo_run_id, executed_at, stages, total_start,
                events_created, alerts_created, rule_detections, ml_detections,
                incident_ids, primary_incident_id, risk_score, risk_level,
                investigation_status, recommendation_count, report_generated,
                attack_stages,
            )

        # --- Stage 4: INVESTIGATE (fault-tolerant) ---
        stage_start = time.monotonic()
        try:
            provider = DemoInvestigatorProvider()
            InvestigationService.investigate(db, primary_incident_id, provider=provider)
            investigation_status = "available"
            stages.append(DemoStageResult(
                stage="INVESTIGATE",
                status="success",
                duration_ms=_elapsed_ms(stage_start),
                details={"provider": "demo"},
            ))
        except Exception as exc:
            logger.warning("Demo investigation failed: %s", exc)
            investigation_status = "failed"
            stages.append(DemoStageResult(
                stage="INVESTIGATE", status="error",
                duration_ms=_elapsed_ms(stage_start), error=str(exc),
            ))

        # --- Stage 5: RECOMMEND (fault-tolerant) ---
        stage_start = time.monotonic()
        try:
            recs = ResponseService.get_recommendations(db, primary_incident_id)
            if recs:
                recommendation_count = recs.get("recommendation_count", 0)
            stages.append(DemoStageResult(
                stage="RECOMMEND",
                status="success",
                duration_ms=_elapsed_ms(stage_start),
                details={"recommendation_count": recommendation_count},
            ))
        except Exception as exc:
            logger.warning("Demo recommendations failed: %s", exc)
            stages.append(DemoStageResult(
                stage="RECOMMEND", status="error",
                duration_ms=_elapsed_ms(stage_start), error=str(exc),
            ))

        # --- Stage 6: REPORT (fault-tolerant) ---
        stage_start = time.monotonic()
        try:
            report = ReportService.generate_report(db, primary_incident_id)
            report_generated = report is not None
            stages.append(DemoStageResult(
                stage="REPORT",
                status="success" if report_generated else "skipped",
                duration_ms=_elapsed_ms(stage_start),
                details={"report_generated": report_generated},
            ))
        except Exception as exc:
            logger.warning("Demo report generation failed: %s", exc)
            stages.append(DemoStageResult(
                stage="REPORT", status="error",
                duration_ms=_elapsed_ms(stage_start), error=str(exc),
            ))

        return _build_response(
            demo_run_id, executed_at, stages, total_start,
            events_created, alerts_created, rule_detections, ml_detections,
            incident_ids, primary_incident_id, risk_score, risk_level,
            investigation_status, recommendation_count, report_generated,
            attack_stages,
        )


def _close_open_incidents(db: Session) -> None:
    """Close all open incidents to ensure scenario isolation.

    Each scenario run should create new incidents, not merge into existing ones.
    By closing open incidents, we force the correlation engine to create fresh
    incidents for the new alerts.
    """
    from app.models.incident import Incident

    open_incidents = (
        db.query(Incident)
        .filter(Incident.status.in_(("new", "investigating")))
        .all()
    )
    for incident in open_incidents:
        incident.status = "closed"
    if open_incidents:
        db.commit()


def _ensure_rules(db: Session) -> None:
    """Seed detection rules if the rules table is empty."""
    from app.models.rule import Rule

    if db.query(Rule).count() > 0:
        return

    default_rules = [
        Rule(
            name="Brute Force Login Detection",
            description="Detects multiple failed login attempts from the same source",
            rule_type="threshold",
            severity="high",
            conditions={
                "type": "combination",
                "logic": "and",
                "conditions": [
                    {"type": "pattern_match", "field": "event_type", "pattern": "failed_login"},
                    {"type": "threshold", "field": "payload.failed_attempts", "operator": "gte", "value": 5},
                ],
            },
            enabled=True,
        ),
        Rule(
            name="Suspicious IP Connection",
            description="Detects connections from known suspicious IP ranges",
            rule_type="pattern_match",
            severity="medium",
            conditions={
                "type": "pattern_match",
                "field": "payload.src_ip",
                "pattern": r"^10\.(0|1)\..*",
            },
            enabled=True,
        ),
        Rule(
            name="Large Data Transfer",
            description="Detects unusually large data transfers that may indicate exfiltration",
            rule_type="threshold",
            severity="critical",
            conditions={
                "type": "threshold",
                "field": "payload.bytes_transferred",
                "operator": "gt",
                "value": 1000000000,
            },
            enabled=True,
        ),
        Rule(
            name="Privilege Escalation Attempt",
            description="Detects privilege escalation events",
            rule_type="pattern_match",
            severity="high",
            conditions={
                "type": "pattern_match",
                "field": "event_type",
                "pattern": "privilege_escalation",
            },
            enabled=True,
        ),
        Rule(
            name="Malware Detection",
            description="Detects known malware signatures",
            rule_type="pattern_match",
            severity="critical",
            conditions={
                "type": "combination",
                "logic": "or",
                "conditions": [
                    {"type": "pattern_match", "field": "event_type", "pattern": "malware_detected"},
                    {"type": "pattern_match", "field": "payload.signature", "pattern": r".*trojan.*|.*ransomware.*|.*virus.*"},
                ],
            },
            enabled=True,
        ),
    ]

    for rule in default_rules:
        db.add(rule)
    db.commit()


def _elapsed_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def _build_response(
    demo_run_id: str,
    executed_at: datetime,
    stages: List[DemoStageResult],
    total_start: float,
    events_created: int,
    alerts_created: int,
    rule_detections: int,
    ml_detections: int,
    incident_ids: List[str],
    primary_incident_id: str | None,
    risk_score: float | None,
    risk_level: str | None,
    investigation_status: str,
    recommendation_count: int,
    report_generated: bool,
    attack_stages: List[str],
) -> DemoAttackScenarioResponse:
    return DemoAttackScenarioResponse(
        demo_run_id=demo_run_id,
        executed_at=executed_at,
        total_duration_ms=_elapsed_ms(total_start),
        stages=stages,
        events_created=events_created,
        alerts_created=alerts_created,
        rule_detections=rule_detections,
        ml_detections=ml_detections,
        incidents_created=len(incident_ids),
        incident_ids=incident_ids,
        primary_incident_id=primary_incident_id,
        risk_score=risk_score,
        risk_level=risk_level,
        investigation_status=investigation_status,
        recommendation_count=recommendation_count,
        report_generated=report_generated,
        attack_stages=attack_stages,
    )
