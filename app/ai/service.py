"""Investigation service — orchestrates the AI investigation workflow.

Pipeline: load incident → load alerts/risk/timeline → build evidence-only
context → call provider → parse + validate response → persist to
``Incident.ai_analysis``.

The numerical risk score always comes from the deterministic risk engine; the
AI layer only narrates and explains it.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.ai.context_builder import build_investigation_context
from app.ai.providers import LLMProvider, get_provider
from app.ai.validation import parse_and_validate
from app.services import (
    CorrelationService,
    IncidentService,
    RiskService,
    TimelineService,
)


class InvestigationService:
    @staticmethod
    def investigate(
        db: Session,
        incident_id: str,
        provider: Optional[LLMProvider] = None,
    ) -> Optional[Dict[str, Any]]:
        """Run an AI investigation for an incident and persist the result.

        Returns the persisted investigation record, or None when the incident
        does not exist. Raises AIInvestigationError subclasses on provider,
        validation, or size failures.
        """
        incident = IncidentService.get_incident(db, incident_id)
        if not incident:
            return None

        alerts = CorrelationService.get_incident_alerts(db, incident_id)
        risk = RiskService.get_risk(db, incident_id)
        timeline = TimelineService.get_timeline(db, incident_id)

        events_by_alert = {a.id: a.event for a in alerts}

        context = build_investigation_context(
            incident, alerts, timeline, risk, events_by_alert=events_by_alert
        )

        active_provider = provider or get_provider()
        raw_response = active_provider.investigate(context.payload)
        report = parse_and_validate(raw_response, context)

        now = datetime.now(timezone.utc)
        record = {
            "investigation": report.model_dump(),
            "provider": active_provider.name,
            "analysis_mode": (
                "DEMO (deterministic mock provider - not a live LLM)"
                if active_provider.name == "demo"
                else "live"
            ),
            "generated_at": now.isoformat(),
            "risk_snapshot": {
                "risk_score": getattr(incident, "risk_score", None),
                "risk_level": getattr(incident, "risk_level", None),
            },
            "evidence_ids": sorted(context.evidence_ids),
            "context_truncated": context.truncated,
        }

        incident.ai_analysis = record
        incident.updated_at = now
        db.commit()
        db.refresh(incident)
        return record

    @staticmethod
    def get_investigation(db: Session, incident_id: str) -> Optional[Dict[str, Any]]:
        """Return the most recent persisted investigation for an incident."""
        incident = IncidentService.get_incident(db, incident_id)
        if not incident:
            return None
        return incident.ai_analysis or None
