"""Response recommendation service — orchestrates the recommendation engine.

Loads the incident's evidence (alerts, risk, AI investigation), runs the
deterministic engine, and persists a snapshot to
``Incident.response_recommendations`` for auditability.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.ai.service import InvestigationService
from app.response.engine import ADVISORY_NOTICE, generate_recommendations
from app.services import CorrelationService, IncidentService, RiskService


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ResponseService:
    @staticmethod
    def build_recommendations(
        incident: Any,
        alerts: List,
        events_by_alert: Optional[Dict[str, Any]],
        risk: Optional[Dict[str, Any]],
        investigation: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Assemble the full recommendations payload (pure, no persistence)."""
        recommendations = generate_recommendations(
            incident,
            alerts,
            events_by_alert=events_by_alert,
            risk=risk,
            investigation=investigation,
        )
        return {
            "incident_id": getattr(incident, "id", None),
            "generated_at": _now_iso(),
            "advisory_notice": ADVISORY_NOTICE,
            "risk_snapshot": {
                "risk_score": (risk or {}).get("risk_score")
                if risk
                else getattr(incident, "risk_score", None),
                "risk_level": (risk or {}).get("risk_level")
                if risk
                else getattr(incident, "risk_level", None),
            },
            "recommendation_count": len(recommendations),
            "recommendations": recommendations,
        }

    @staticmethod
    def get_recommendations(
        db: Session,
        incident_id: str,
        persist: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """Generate recommendations for an incident and persist the snapshot.

        Returns the recommendations payload, or None when the incident does
        not exist.
        """
        incident = IncidentService.get_incident(db, incident_id)
        if not incident:
            return None

        alerts = CorrelationService.get_incident_alerts(db, incident_id)
        events_by_alert = {a.id: a.event for a in alerts}
        risk = RiskService.get_risk(db, incident_id)
        investigation = InvestigationService.get_investigation(db, incident_id)

        result = ResponseService.build_recommendations(
            incident, alerts, events_by_alert, risk, investigation
        )

        if persist:
            incident.response_recommendations = result
            incident.updated_at = datetime.now(timezone.utc)
            db.commit()

        return result
