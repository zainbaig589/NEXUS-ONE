"""Incident report service — orchestrates report generation and retrieval.

Pipeline: load incident → load alerts/risk/timeline/investigation →
build recommendations (deterministic engine) → assemble the structured
report → persist a snapshot (``incident_reports`` table) plus the
recommendation snapshot on the incident.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.ai.service import InvestigationService
from app.models.incident_report import IncidentReportRecord
from app.reports.generator import build_incident_report
from app.reports.schemas import IncidentReport
from app.response.service import ResponseService
from app.services import CorrelationService, IncidentService, RiskService, TimelineService


class ReportService:
    @staticmethod
    def generate_report(
        db: Session,
        incident_id: str,
        persist: bool = True,
    ) -> Optional[IncidentReport]:
        """Generate a full incident report and persist it.

        Returns the report model, or None when the incident does not exist.
        """
        incident = IncidentService.get_incident(db, incident_id)
        if not incident:
            return None

        alerts = CorrelationService.get_incident_alerts(db, incident_id)
        events_by_alert = {a.id: a.event for a in alerts}
        risk = RiskService.get_risk(db, incident_id)
        timeline = TimelineService.get_timeline(db, incident_id)
        investigation = InvestigationService.get_investigation(db, incident_id)

        recommendations = ResponseService.build_recommendations(
            incident, alerts, events_by_alert, risk, investigation
        )
        report = build_incident_report(
            incident,
            alerts,
            events_by_alert,
            risk,
            timeline,
            investigation,
            recommendations,
        )

        if persist:
            now = datetime.now(timezone.utc)
            incident.response_recommendations = recommendations
            incident.updated_at = now
            db.add(
                IncidentReportRecord(
                    incident_id=incident_id,
                    format_version=report.format_version,
                    content=report.model_dump(),
                )
            )
            db.commit()

        return report

    @staticmethod
    def get_report(db: Session, incident_id: str) -> Optional[Dict[str, Any]]:
        """Return the most recently generated report content, or None."""
        record = (
            db.query(IncidentReportRecord)
            .filter(IncidentReportRecord.incident_id == incident_id)
            .order_by(IncidentReportRecord.generated_at.desc())
            .first()
        )
        if not record:
            return None
        return record.content
