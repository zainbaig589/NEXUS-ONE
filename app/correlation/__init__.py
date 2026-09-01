"""Event correlation engine.

Groups related security alerts into incidents using a deterministic,
weighted multi-factor scoring algorithm. The engine is:

- Deterministic: same inputs always produce the same grouping.
- Explainable: every grouping decision is stored as human-readable reasons.
- Idempotent: re-running correlation does not create duplicate incidents.
- Configurable: time window and threshold can be tuned.
"""

from datetime import datetime
from typing import List, Dict, Set, Tuple, Optional, Any

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Incident
from app.correlation.scorer import (
    compute_score,
    extract_indicators,
    max_severity,
    CORRELATION_THRESHOLD,
    TIME_WINDOW_MINUTES,
)
from app.risk.scorer import calculate_risk
from app.timeline import build_timeline
from app.attack_stages import classify_incident


class CorrelationEngine:
    """Correlates related security alerts into incidents."""

    def __init__(
        self,
        db: Session,
        threshold: float = CORRELATION_THRESHOLD,
        time_window_minutes: int = TIME_WINDOW_MINUTES,
    ):
        self.db = db
        self.threshold = threshold
        self.time_window_minutes = time_window_minutes
        self.created_incident_ids: Set[str] = set()
        self.updated_incident_ids: Set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate(self, alert_ids: Optional[List[str]] = None) -> List[Incident]:
        """Run correlation on alerts. Returns list of incidents created or updated.

        If alert_ids is provided, only those alerts are considered.
        Otherwise, all alerts with status='new' (uncorrelated) are processed.
        """
        self.created_incident_ids = set()
        self.updated_incident_ids = set()
        if alert_ids is not None:
            alerts = (
                self.db.query(Alert)
                .filter(Alert.id.in_(alert_ids), Alert.incident_id == None)  # noqa: E711
                .all()
            )
        else:
            alerts = (
                self.db.query(Alert)
                .filter(Alert.status == "new", Alert.incident_id == None)  # noqa: E711
                .order_by(Alert.created_at.asc())
                .all()
            )

        if not alerts:
            return []

        open_incidents = (
            self.db.query(Incident)
            .filter(Incident.status.in_(("new", "investigating")))
            .all()
        )

        touched_incidents: List[Incident] = []

        for alert in alerts:
            indicators = self._alert_indicators(alert)
            event = self._alert_event(alert)

            best_incident, best_score, best_reasons = self._find_best_incident(
                alert, indicators, event, open_incidents
            )

            if best_incident is not None:
                self._merge_into_incident(best_incident, alert, indicators, event, best_score, best_reasons)
                if best_incident.id not in self.created_incident_ids:
                    self.updated_incident_ids.add(best_incident.id)
                if best_incident not in touched_incidents:
                    touched_incidents.append(best_incident)
            else:
                new_incident = self._create_incident(alert, indicators, event)
                self.created_incident_ids.add(new_incident.id)
                open_incidents.append(new_incident)
                touched_incidents.append(new_incident)

        self.db.commit()
        for inc in touched_incidents:
            self.db.refresh(inc)
        return touched_incidents

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _alert_indicators(self, alert: Alert) -> Dict[str, Set[str]]:
        """Extract indicators from the event that generated this alert."""
        event = self._alert_event(alert)
        if event is None:
            return {"source_ips": set(), "destination_ips": set(), "users": set(), "hosts": set(), "iocs": set()}
        return extract_indicators(event)

    def _alert_event(self, alert: Alert) -> Optional[Event]:
        return self.db.query(Event).filter(Event.id == alert.event_id).first()

    def _incident_indicators(self, incident: Incident) -> Dict[str, Set[str]]:
        """Reconstruct indicator sets from the incident's stored JSON lists."""
        return {
            "source_ips": set(incident.source_ips or []),
            "destination_ips": set(incident.destination_ips or []),
            "users": set(incident.users or []),
            "hosts": set(incident.hosts or []),
            "iocs": set(),  # IOCs are not stored on incident; skip for now
        }

    def _find_best_incident(
        self,
        alert: Alert,
        indicators: Dict[str, Set[str]],
        event: Optional[Event],
        open_incidents: List[Incident],
    ) -> Tuple[Optional[Incident], float, List[str]]:
        """Score the alert against every open incident. Return the best match."""
        best_incident: Optional[Incident] = None
        best_score = 0.0
        best_reasons: List[str] = []

        event_type = event.event_type if event else ""
        event_time = event.timestamp if event else None

        for incident in open_incidents:
            inc_indicators = self._incident_indicators(incident)
            # Use the incident's last_seen as its reference time
            inc_time = incident.last_seen
            # Use the highest-severity event type seen in the incident
            # (approximate with incident title or first event type)
            inc_event_type = ""  # not used heavily; related_event_type still fires on shared types

            score, reasons = compute_score(
                indicators,
                inc_indicators,
                event_time,
                inc_time,
                event_type,
                inc_event_type,
                self.time_window_minutes,
            )

            # Bonus: if the alert's event_type matches any of the incident's alert event_types
            inc_event_types = self._incident_event_types(incident)
            if event_type and any(
                _types_related(event_type, t) for t in inc_event_types
            ):
                from app.correlation.scorer import SCORE_WEIGHTS
                if "related event types" not in " ".join(reasons):
                    score += SCORE_WEIGHTS["related_event_type"]
                    reasons.append(f"related to incident event types {inc_event_types}")

            score = min(max(score, 0.0), 1.0)
            if score > best_score and score >= self.threshold:
                best_score = score
                best_reasons = reasons
                best_incident = incident

        return best_incident, best_score, best_reasons

    def _incident_event_types(self, incident: Incident) -> Set[str]:
        """Return the set of event_types for alerts in this incident."""
        if not incident.alert_ids:
            return set()
        alerts = self.db.query(Alert).filter(Alert.id.in_(incident.alert_ids)).all()
        types = set()
        for a in alerts:
            ev = self.db.query(Event).filter(Event.id == a.event_id).first()
            if ev:
                types.add(ev.event_type)
        return types

    def _merge_into_incident(
        self,
        incident: Incident,
        alert: Alert,
        indicators: Dict[str, Set[str]],
        event: Optional[Event],
        score: float,
        reasons: List[str],
    ):
        """Add an alert to an existing incident and refresh all aggregates."""
        current_ids = list(incident.alert_ids or [])
        if alert.id not in current_ids:
            current_ids.append(alert.id)
        incident.alert_ids = current_ids
        incident.alert_count = len(current_ids)

        # Update temporal bounds
        event_time = event.timestamp if event else alert.created_at
        if event_time:
            if incident.first_seen is None or event_time < incident.first_seen:
                incident.first_seen = event_time
            if incident.last_seen is None or event_time > incident.last_seen:
                incident.last_seen = event_time

        # Update indicator sets (union)
        incident.source_ips = sorted(set(incident.source_ips or []) | indicators.get("source_ips", set()))
        incident.destination_ips = sorted(set(incident.destination_ips or []) | indicators.get("destination_ips", set()))
        incident.users = sorted(set(incident.users or []) | indicators.get("users", set()))
        incident.hosts = sorted(set(incident.hosts or []) | indicators.get("hosts", set()))

        # Update correlation score (keep max) and reasons (accumulate, dedupe)
        bounded_score = round(min(max(score, 0.0), 1.0), 4)
        if incident.correlation_score is None or bounded_score > incident.correlation_score:
            incident.correlation_score = bounded_score

        existing_reasons = list(incident.correlation_reasons or [])
        for r in reasons:
            if r not in existing_reasons:
                existing_reasons.append(r)
        incident.correlation_reasons = existing_reasons

        # Refresh severity to max across all alerts
        self._refresh_severity(incident)

        # Update title/description for multi-alert incidents
        self._refresh_title(incident)

        # Link the alert to the incident and mark it correlated
        alert.incident_id = incident.id
        alert.status = "correlated"

        # Refresh risk, timeline, and attack stages from the full set of alerts
        self._enrich_incident(incident)

    def _create_incident(
        self,
        alert: Alert,
        indicators: Dict[str, Set[str]],
        event: Optional[Event],
    ) -> Incident:
        """Create a new incident from a single uncorrelated alert."""
        event_time = event.timestamp if event else alert.created_at
        event_type = event.event_type if event else ""

        incident = Incident(
            title=alert.rule_name,
            severity=alert.severity,
            status="new",
            description=f"Incident opened by rule '{alert.rule_name}'.",
            alert_ids=[alert.id],
            alert_count=1,
            correlation_score=1.0,  # Seed incident is a perfect self-match
            correlation_reasons=[f"initial alert from rule '{alert.rule_name}'"],
            first_seen=event_time,
            last_seen=event_time,
            source_ips=sorted(indicators.get("source_ips", set())),
            destination_ips=sorted(indicators.get("destination_ips", set())),
            users=sorted(indicators.get("users", set())),
            hosts=sorted(indicators.get("hosts", set())),
        )
        self.db.add(incident)
        self.db.flush()  # Get the incident.id

        alert.incident_id = incident.id
        alert.status = "correlated"

        # Compute initial risk, timeline, and attack stages
        self._enrich_incident(incident)

        return incident

    def _enrich_incident(self, incident: Incident):
        """Recompute and store risk score, timeline, and attack stages."""
        if not incident.alert_ids:
            return

        alerts = self.db.query(Alert).filter(Alert.id.in_(incident.alert_ids)).all()
        event_ids = [a.event_id for a in alerts if a.event_id]
        events = (
            self.db.query(Event).filter(Event.id.in_(event_ids)).all()
            if event_ids
            else []
        )
        events_by_alert = {a.id: next((e for e in events if e.id == a.event_id), None) for a in alerts}

        risk_result = calculate_risk(incident, alerts, events_by_alert)
        incident.risk_score = risk_result["risk_score"]
        incident.risk_level = risk_result["risk_level"]
        incident.risk_factors = risk_result["contributing_factors"]

        timeline_result = build_timeline(incident, alerts, events_by_alert)
        incident.attack_timeline = _serialize_timeline(timeline_result["entries"])

        incident.attack_stages = classify_incident([e for e in events_by_alert.values() if e is not None])

    def _refresh_severity(self, incident: Incident):
        """Set incident severity to the max severity of its alerts."""
        if not incident.alert_ids:
            return
        alerts = self.db.query(Alert).filter(Alert.id.in_(incident.alert_ids)).all()
        incident.severity = max_severity(a.severity for a in alerts)

    def _refresh_title(self, incident: Incident):
        """Update the incident title based on the number of distinct rules."""
        if not incident.alert_ids or len(incident.alert_ids) < 2:
            return
        alerts = self.db.query(Alert).filter(Alert.id.in_(incident.alert_ids)).all()
        distinct_rules = {a.rule_name for a in alerts}
        if len(distinct_rules) >= 3:
            incident.title = "Multi-Stage Attack"
        else:
            incident.title = "Correlated Security Incident"
        incident.description = "Correlated because: " + "; ".join(incident.correlation_reasons or [])


def _types_related(type_a: str, type_b: str) -> bool:
    from app.correlation.scorer import RELATED_EVENT_GROUPS
    if type_a == type_b:
        return True
    for group in RELATED_EVENT_GROUPS:
        if type_a in group and type_b in group:
            return True
    return False


def _serialize_timeline(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert timeline entries into JSON-safe dicts (datetime -> ISO strings)."""
    serialized = []
    for entry in entries:
        serialized_entry = dict(entry)
        ts = serialized_entry.get("timestamp")
        if isinstance(ts, datetime):
            serialized_entry["timestamp"] = ts.isoformat()
        serialized.append(serialized_entry)
    return serialized
