"""Builds the structured, evidence-only context handed to the AI provider.

The context is assembled exclusively from already-computed artifacts
(incident record, correlated alerts, deterministic risk score, attack
timeline). No database internals, configuration, or secrets are included.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from app.ai.errors import AIContextTooLargeError
from app.config import settings


@dataclass
class InvestigationContext:
    """Structured evidence payload plus the citation IDs it legitimises."""

    payload: Dict[str, Any]
    evidence_ids: Set[str] = field(default_factory=set)
    truncated: bool = False

    def to_json(self) -> str:
        return json.dumps(self.payload, indent=2, default=str, ensure_ascii=False)


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if value is not None else None


def _ml_anomaly(event: Any) -> Optional[Dict[str, Any]]:
    payload = getattr(event, "payload", None) or {}
    if not isinstance(payload, dict):
        return None
    keys = ("anomaly_score", "is_anomaly", "confidence", "reason")
    data = {k: payload[k] for k in keys if k in payload}
    return data or None


def build_investigation_context(
    incident: Any,
    alerts: List[Any],
    timeline: Dict[str, Any],
    risk: Optional[Dict[str, Any]],
    events_by_alert: Optional[Dict[str, Any]] = None,
    max_alerts: Optional[int] = None,
    max_context_chars: Optional[int] = None,
) -> InvestigationContext:
    """Build the OBSERVED EVIDENCE payload for an incident.

    ``timeline`` is the output of ``app.timeline.builder.build_timeline`` and
    ``risk`` the output of ``app.risk.scorer.calculate_risk`` — both already
    deterministic, explainable artifacts.
    """
    max_alerts = max_alerts if max_alerts is not None else settings.LLM_MAX_ALERTS_IN_CONTEXT
    max_context_chars = (
        max_context_chars if max_context_chars is not None else settings.LLM_MAX_CONTEXT_CHARS
    )

    entries = list(timeline.get("entries", []))
    alerts_by_id = {getattr(a, "id", None): a for a in alerts}

    truncated = len(entries) > max_alerts
    if truncated:
        entries = entries[:max_alerts]

    alert_evidence = []
    evidence_ids: Set[str] = set()

    for entry in entries:
        alert = alerts_by_id.get(entry.get("alert_id"))
        event = (
            events_by_alert.get(entry.get("alert_id"))
            if events_by_alert
            else getattr(alert, "event", None)
        )

        alert_citation = f"alert-{entry['alert_id']}" if entry.get("alert_id") else None
        event_citation = f"event-{entry['event_id']}" if entry.get("event_id") else None
        for citation in (alert_citation, event_citation):
            if citation:
                evidence_ids.add(citation)

        alert_evidence.append(
            {
                "id": alert_citation,
                "event_id": event_citation,
                "timestamp": _iso(entry.get("timestamp")),
                "event_type": entry.get("event_type"),
                "rule_name": getattr(alert, "rule_name", None),
                "severity": entry.get("severity"),
                "detection_method": entry.get("detection_method"),
                "detection_reason": entry.get("description"),
                "source_ip": entry.get("source_ip"),
                "destination_ip": entry.get("destination_ip"),
                "user": entry.get("user"),
                "host": entry.get("host"),
                "ml_anomaly": _ml_anomaly(event),
                "potential_attack_stage": entry.get("stage"),
            }
        )

    stages = list(getattr(incident, "attack_stages", None) or [])
    stage_names = [s.replace("Potential stage: ", "") for s in stages]

    risk_block = None
    if risk:
        risk_block = {
            "risk_score": risk.get("risk_score"),
            "risk_level": risk.get("risk_level"),
            "contributing_factors": risk.get("contributing_factors", []),
            "scoring_explanation": risk.get("scoring_explanation"),
        }

    payload: Dict[str, Any] = {
        "incident": {
            "id": getattr(incident, "id", None),
            "title": getattr(incident, "title", None),
            "severity": getattr(incident, "severity", None),
            "status": getattr(incident, "status", None),
            "description": getattr(incident, "description", None),
            "first_seen": _iso(getattr(incident, "first_seen", None)),
            "last_seen": _iso(getattr(incident, "last_seen", None)),
            "alert_count": getattr(incident, "alert_count", 0),
            "correlation_score": getattr(incident, "correlation_score", None),
            "correlation_reasons": list(getattr(incident, "correlation_reasons", None) or []),
        },
        "deterministic_risk_assessment": risk_block,
        "alerts": alert_evidence,
        "timeline": {
            "first_seen": _iso(timeline.get("first_seen")),
            "last_seen": _iso(timeline.get("last_seen")),
            "duration_seconds": timeline.get("duration_seconds", 0),
        },
        "potential_attack_stages": stage_names,
        "observed_entities": {
            "hosts": list(getattr(incident, "hosts", None) or []),
            "users": list(getattr(incident, "users", None) or []),
            "source_ips": list(getattr(incident, "source_ips", None) or []),
            "destination_ips": list(getattr(incident, "destination_ips", None) or []),
        },
    }

    if truncated:
        payload["context_notes"] = {
            "alerts_truncated": True,
            "note": (
                f"Only the first {max_alerts} alerts (chronological) are included; "
                "the incident contains more alerts that are not shown."
            ),
        }

    serialized_len = len(json.dumps(payload, default=str, ensure_ascii=False))
    if serialized_len > max_context_chars:
        raise AIContextTooLargeError(
            f"Incident evidence context is too large ({serialized_len} characters; "
            f"limit is {max_context_chars}). Investigate a narrower incident or raise "
            "LLM_MAX_CONTEXT_CHARS."
        )

    return InvestigationContext(payload=payload, evidence_ids=evidence_ids, truncated=truncated)
