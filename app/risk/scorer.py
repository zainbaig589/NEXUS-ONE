"""Deterministic, explainable incident risk scoring.

The risk score is a weighted sum of transparent signals. All inputs are
already available on the correlated Incident model or its alerts/events.
Weights are centralised so they can be tuned without rewriting formulae.
"""

from typing import Any, Dict, List, Optional, Tuple

from app.correlation.scorer import SEVERITY_ORDER

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

RISK_WEIGHTS = {
    # Severity of the incident (already the max across alerts)
    "severity": 0.18,
    # Number of correlated alerts
    "alert_count": 0.16,
    # Correlation confidence/score
    "correlation_score": 0.12,
    # Spread of affected infrastructure
    "host_count": 0.10,
    "user_count": 0.08,
    "ip_count": 0.08,
    # ML anomaly score when available (0-1)
    "anomaly_score": 0.12,
    # Attack progression: number of distinct kill-chain stages
    "stage_progression": 0.10,
    # Event frequency/density inside the incident time window
    "time_density": 0.06,
}

# Risk level thresholds (inclusive lower bound)
RISK_LEVELS = [
    (75.0, "CRITICAL"),
    (50.0, "HIGH"),
    (25.0, "MEDIUM"),
    (0.0, "LOW"),
]

# Maximum reference values used to normalise each signal to 0-100.
_MAX_ALERT_COUNT = 10
_MAX_HOST_COUNT = 5
_MAX_USER_COUNT = 5
_MAX_IP_COUNT = 5
_MAX_STAGES = 5
_TIME_DENSITY_HIGH = 6.0  # events per hour that gives full score


def _normalise(value: float, maximum: float) -> float:
    """Clamp value to [0, maximum] and return percentage."""
    if maximum <= 0:
        return 0.0
    return min(value, maximum) / maximum * 100.0


def _severity_value(severity: Optional[str]) -> int:
    return SEVERITY_ORDER.get(severity or "info", 1)


def _max_anomaly_score(alerts: List[Any], events_by_alert: Optional[Dict[str, Any]] = None) -> float:
    """Return the highest ML anomaly score found in the alerts/events (0-1)."""
    max_score = 0.0
    for alert in alerts:
        score = None
        # Direct attribute if present
        if hasattr(alert, "anomaly_score") and alert.anomaly_score is not None:
            try:
                score = float(alert.anomaly_score)
            except (TypeError, ValueError):
                score = None
        # Payload on the event
        if score is None and events_by_alert:
            event = events_by_alert.get(getattr(alert, "id", None))
            payload = getattr(event, "payload", {}) or {}
            raw = payload.get("anomaly_score")
            if raw is not None:
                try:
                    score = float(raw)
                except (TypeError, ValueError):
                    score = None
        if score is not None and score > max_score:
            max_score = score
    return min(max_score, 1.0)


def _time_density_score(alert_count: int, first_seen: Optional[Any], last_seen: Optional[Any]) -> float:
    """Score based on events per hour inside the incident window."""
    if not first_seen or not last_seen or alert_count <= 0:
        return 0.0
    try:
        duration_hours = (last_seen - first_seen).total_seconds() / 3600.0
    except (TypeError, AttributeError):
        return 0.0
    duration_hours = max(duration_hours, 1.0 / 60.0)  # at least 1 minute
    events_per_hour = alert_count / duration_hours
    return _normalise(events_per_hour, _TIME_DENSITY_HIGH)


def calculate_risk(
    incident: Any,
    alerts: List[Any],
    events_by_alert: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Calculate deterministic risk for an incident.

    Returns a dict with:
        risk_score: float 0-100
        risk_level: LOW / MEDIUM / HIGH / CRITICAL
        contributing_factors: list of human-readable factor strings
        scoring_explanation: single human-readable sentence
    """
    # Raw signals
    sev = _severity_value(getattr(incident, "severity", "info"))
    severity_score = sev / max(SEVERITY_ORDER.values()) * 100.0

    alert_count = getattr(incident, "alert_count", len(alerts)) or 0
    alert_count_score = _normalise(alert_count, _MAX_ALERT_COUNT)

    correlation_score = getattr(incident, "correlation_score", 0.0) or 0.0
    correlation_score_score = min(correlation_score, 1.0) * 100.0

    hosts = getattr(incident, "hosts", []) or []
    users = getattr(incident, "users", []) or []
    src_ips = getattr(incident, "source_ips", []) or []
    dst_ips = getattr(incident, "destination_ips", []) or []

    host_count_score = _normalise(len(hosts), _MAX_HOST_COUNT)
    user_count_score = _normalise(len(users), _MAX_USER_COUNT)
    ip_count_score = _normalise(len(src_ips) + len(dst_ips), _MAX_IP_COUNT)

    anomaly_score = _max_anomaly_score(alerts, events_by_alert)
    anomaly_score_score = anomaly_score * 100.0

    # Stages: use alerts if available (classify_event handles Alert objects)
    from app.attack_stages import get_distinct_stages
    distinct_stages = get_distinct_stages(alerts)
    stage_progression_score = _normalise(len(distinct_stages), _MAX_STAGES)

    time_density = _time_density_score(
        alert_count,
        getattr(incident, "first_seen", None),
        getattr(incident, "last_seen", None),
    )

    # Weighted components
    components = {
        "severity": severity_score * RISK_WEIGHTS["severity"],
        "alert_count": alert_count_score * RISK_WEIGHTS["alert_count"],
        "correlation_score": correlation_score_score * RISK_WEIGHTS["correlation_score"],
        "host_count": host_count_score * RISK_WEIGHTS["host_count"],
        "user_count": user_count_score * RISK_WEIGHTS["user_count"],
        "ip_count": ip_count_score * RISK_WEIGHTS["ip_count"],
        "anomaly_score": anomaly_score_score * RISK_WEIGHTS["anomaly_score"],
        "stage_progression": stage_progression_score * RISK_WEIGHTS["stage_progression"],
        "time_density": time_density * RISK_WEIGHTS["time_density"],
    }

    total = round(sum(components.values()), 4)
    total = max(0.0, min(100.0, total))

    risk_level = "LOW"
    for threshold, level in RISK_LEVELS:
        if total >= threshold:
            risk_level = level
            break

    contributing_factors = _build_factors(
        components,
        severity=getattr(incident, "severity", "info"),
        alert_count=alert_count,
        hosts=len(hosts),
        users=len(users),
        ips=len(src_ips) + len(dst_ips),
        anomaly_score=anomaly_score,
        stages=distinct_stages,
    )

    explanation = _build_explanation(
        risk_level=risk_level,
        score=total,
        factors=contributing_factors,
    )

    return {
        "risk_score": total,
        "risk_level": risk_level,
        "contributing_factors": contributing_factors,
        "scoring_explanation": explanation,
    }


def _build_factors(
    components: Dict[str, float],
    severity: str,
    alert_count: int,
    hosts: int,
    users: int,
    ips: int,
    anomaly_score: float,
    stages: List[str],
) -> List[str]:
    """Produce human-readable bullets for signals that materially contribute."""
    factors: List[str] = []

    if components["severity"] >= 8.0:
        factors.append(f"incident severity is {severity}")

    if alert_count >= 2:
        factors.append(f"incident contains {alert_count} correlated alerts")

    if components["correlation_score"] >= 6.0:
        factors.append("strong correlation confidence")

    if hosts >= 1:
        factors.append(f"involves {hosts} affected host{'s' if hosts > 1 else ''}")

    if users >= 1:
        factors.append(f"involves {users} affected user{'s' if users > 1 else ''}")

    if ips >= 1:
        factors.append(f"involves {ips} observed IP{'s' if ips > 1 else ''}")

    if anomaly_score >= 0.5:
        factors.append(f"high ML anomaly score ({round(anomaly_score, 2)})")

    if stages:
        stage_text = ", ".join(stages)
        factors.append(f"potential attack stages: {stage_text}")

    if not factors:
        factors.append("low-signal incident")

    return factors


def _build_explanation(risk_level: str, score: float, factors: List[str]) -> str:
    """Assemble a single sentence explanation."""
    prefix = f"Risk assessed as {risk_level} ({round(score, 1)}/100)"
    if not factors:
        return f"{prefix}. No significant contributing factors were identified."
    joined = "; ".join(factors)
    return f"{prefix} because {joined}."


def risk_level_from_score(score: float) -> str:
    for threshold, level in RISK_LEVELS:
        if score >= threshold:
            return level
    return "LOW"
