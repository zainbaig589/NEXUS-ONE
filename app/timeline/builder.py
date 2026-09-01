"""Attack timeline reconstruction from correlated incidents."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.correlation.scorer import extract_indicators
from app.attack_stages import classify_event


def _first(values: set) -> Optional[str]:
    """Return the first sorted value from a set, or None."""
    if not values:
        return None
    return sorted(values)[0]


def build_timeline(
    incident: Any,
    alerts: List[Any],
    events_by_alert: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a chronological attack timeline for an incident.

    Returns a dict with:
        incident_id, first_seen, last_seen, duration_seconds, entries

    Each entry preserves the original alert/event evidence and includes a
    potential attack stage where one can be determined.
    """
    entries: List[Dict[str, Any]] = []

    for alert in alerts:
        alert_id = getattr(alert, "id", None)
        event = events_by_alert.get(alert_id) if events_by_alert else getattr(alert, "event", None)

        if event is None:
            continue

        indicators = extract_indicators(event)
        stage = classify_event(event) or classify_event(alert)

        ts = getattr(event, "timestamp", None)
        entry = {
            "timestamp": ts,
            "event_id": getattr(event, "id", None),
            "alert_id": alert_id,
            "event_type": getattr(event, "event_type", None),
            "source_ip": _first(indicators.get("source_ips", set())),
            "destination_ip": _first(indicators.get("destination_ips", set())),
            "user": _first(indicators.get("users", set())),
            "host": _first(indicators.get("hosts", set())),
            "severity": getattr(event, "severity", getattr(alert, "severity", "info")),
            "detection_method": getattr(alert, "detection_source", "rule"),
            "description": getattr(alert, "description", None) or f"Alert from rule '{getattr(alert, 'rule_name', 'unknown')}'",
            "stage": f"Potential stage: {stage}" if stage else None,
        }
        entries.append(entry)

    # Sort chronologically by event timestamp
    entries.sort(key=lambda e: e["timestamp"] or datetime.min.replace(tzinfo=timezone.utc))

    first_seen = None
    last_seen = None
    duration_seconds = 0

    timestamps = [e["timestamp"] for e in entries if e["timestamp"] is not None]
    if timestamps:
        first_seen = min(timestamps)
        last_seen = max(timestamps)
        duration_seconds = int((last_seen - first_seen).total_seconds())

    return {
        "incident_id": getattr(incident, "id", None),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "duration_seconds": duration_seconds,
        "entries": entries,
    }
