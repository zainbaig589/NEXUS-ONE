"""Risk scoring service — computes incident risk on demand."""

from typing import Dict, Any

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Incident
from app.risk.scorer import calculate_risk


class RiskService:
    @staticmethod
    def get_risk(db: Session, incident_id: str) -> Dict[str, Any]:
        """Return the current risk assessment for an incident."""
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return None

        alerts = []
        events_by_alert = {}
        if incident.alert_ids:
            alerts = db.query(Alert).filter(Alert.id.in_(incident.alert_ids)).all()
            event_ids = [a.event_id for a in alerts if a.event_id]
            events = db.query(Event).filter(Event.id.in_(event_ids)).all() if event_ids else []
            events_by_alert = {
                a.id: next((e for e in events if e.id == a.event_id), None) for a in alerts
            }

        result = calculate_risk(incident, alerts, events_by_alert)
        result["incident_id"] = incident.id
        return result
