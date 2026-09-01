"""Correlation service — orchestrates the CorrelationEngine."""

from dataclasses import dataclass
from typing import List, Optional, Set

from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.correlation import CorrelationEngine
from app.correlation.scorer import CORRELATION_THRESHOLD, TIME_WINDOW_MINUTES


@dataclass
class CorrelationRunResult:
    incidents: List[Incident]
    created_incident_ids: Set[str]
    updated_incident_ids: Set[str]


class CorrelationService:
    @staticmethod
    def run(
        db: Session,
        alert_ids: Optional[List[str]] = None,
        threshold: Optional[float] = None,
        time_window_minutes: Optional[int] = None,
    ) -> List[Incident]:
        """Run correlation and return list of incidents created or updated."""
        return CorrelationService.run_with_stats(
            db,
            alert_ids=alert_ids,
            threshold=threshold,
            time_window_minutes=time_window_minutes,
        ).incidents

    @staticmethod
    def run_with_stats(
        db: Session,
        alert_ids: Optional[List[str]] = None,
        threshold: Optional[float] = None,
        time_window_minutes: Optional[int] = None,
    ) -> CorrelationRunResult:
        """Run correlation and retain creation and update provenance."""
        engine = CorrelationEngine(
            db,
            threshold=threshold if threshold is not None else CORRELATION_THRESHOLD,
            time_window_minutes=time_window_minutes if time_window_minutes is not None else TIME_WINDOW_MINUTES,
        )
        incidents = engine.correlate(alert_ids=alert_ids)
        return CorrelationRunResult(
            incidents=incidents,
            created_incident_ids=set(engine.created_incident_ids),
            updated_incident_ids=set(engine.updated_incident_ids),
        )

    @staticmethod
    def get_incident_alerts(db: Session, incident_id: str):
        """Return all alerts belonging to an incident."""
        from app.models.alert import Alert
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident or not incident.alert_ids:
            return []
        return (
            db.query(Alert)
            .filter(Alert.id.in_(incident.alert_ids))
            .order_by(Alert.created_at.asc())
            .all()
        )
