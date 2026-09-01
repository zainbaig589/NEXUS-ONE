"""Correlation scoring and indicator extraction.

The correlation algorithm uses a weighted multi-factor scoring system.
Each matching indicator between two alerts adds to the total score.
Alerts with a combined score >= CORRELATION_THRESHOLD are considered related.

Scoring weights may sum above 1.0 when every factor matches. The final score is
clamped to the inclusive range 0.0–1.0 after all matching factors are applied:
    same_source_ip:      0.25
    same_destination_ip: 0.25
    same_user:           0.20
    same_host:           0.15
    same_ioc:            0.20
    related_event_type:  0.10
    time_proximity:      up to 0.15 (decays with distance)

Threshold: 0.35 — any two alerts scoring at or above this are correlated.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, Set, Tuple, List, Optional


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

SCORE_WEIGHTS = {
    "same_source_ip": 0.25,
    "same_destination_ip": 0.25,
    "same_user": 0.20,
    "same_host": 0.15,
    "same_ioc": 0.20,
    "related_event_type": 0.10,
    "time_proximity": 0.15,
}

CORRELATION_THRESHOLD = 0.35
TIME_WINDOW_MINUTES = 15

SEVERITY_ORDER = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

# Event types that are considered logically related (e.g., stages of an attack)
RELATED_EVENT_GROUPS = [
    {"failed_login", "successful_login", "account_lockout", "privilege_escalation"},
    {"malware_detected", "file_download", "process_execution", "registry_modification"},
    {"connection", "data_transfer", "dns_query", "network_scan"},
    {"privilege_escalation", "process_execution", "lateral_movement"},
]


# -----------------------------------------------------------------------------
# Indicator extraction
# -----------------------------------------------------------------------------

def extract_indicators(event) -> Dict[str, Set[str]]:
    """Extract source_ips, destination_ips, users, hosts, and iocs from an event.

    Walks the event payload (a dict) and matches field names against known
    conventions for each indicator category. IP fields are additionally
    validated against a loose IPv4/IPv6-ish regex.
    """
    payload = getattr(event, "payload", None) or {}
    event_type = getattr(event, "event_type", "") or ""

    indicators: Dict[str, Set[str]] = {
        "source_ips": set(),
        "destination_ips": set(),
        "users": set(),
        "hosts": set(),
        "iocs": set(),
    }

    src_prefixes = ("src", "source", "client", "attacker", "remote")
    dst_prefixes = ("dst", "dest", "destination", "target", "server")
    ip_suffixes = ("_ip", "_addr", "_address", "ip")

    for key, value in payload.items():
        if not isinstance(value, str) or not value.strip():
            continue
        v = value.strip()
        key_lower = key.lower()

        # IP detection: field name hints + looks-like-IP heuristic
        is_ip_field = (
            any(key_lower.startswith(p) for p in src_prefixes + dst_prefixes)
            and any(s in key_lower for s in ip_suffixes)
        ) or _looks_like_ip(v)

        if is_ip_field:
            if any(key_lower.startswith(p) for p in src_prefixes):
                indicators["source_ips"].add(v)
            elif any(key_lower.startswith(p) for p in dst_prefixes):
                indicators["destination_ips"].add(v)
            else:
                indicators["source_ips"].add(v)  # default bucket

        # User detection
        if key_lower in {"user", "username", "account", "login", "uid", "subject"}:
            indicators["users"].add(v)

        # Host detection
        if key_lower in {"host", "hostname", "device", "machine", "computer", "endpoint"}:
            indicators["hosts"].add(v)

        # IOC detection
        if key_lower in {"signature", "hash", "md5", "sha1", "sha256", "file", "iocs", "indicator"}:
            indicators["iocs"].add(v)

    return indicators


def _looks_like_ip(value: str) -> bool:
    """Loose check for IPv4 addresses."""
    parts = value.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return False


# -----------------------------------------------------------------------------
# Scoring
# -----------------------------------------------------------------------------

def compute_score(
    ind_a: Dict[str, Set[str]],
    ind_b: Dict[str, Set[str]],
    time_a: Optional[datetime],
    time_b: Optional[datetime],
    event_type_a: str,
    event_type_b: str,
    time_window_minutes: int = TIME_WINDOW_MINUTES,
) -> Tuple[float, List[str]]:
    """Compute correlation score and explanatory reasons between two alerts.

    Returns (score, reasons) where score is in [0.0, ~1.0] and reasons is a
    list of human-readable strings explaining which factors matched.
    """
    score = 0.0
    reasons: List[str] = []

    # Source IPs
    shared_src = ind_a.get("source_ips", set()) & ind_b.get("source_ips", set())
    if shared_src:
        score += SCORE_WEIGHTS["same_source_ip"]
        ips = ", ".join(sorted(shared_src))
        reasons.append(f"share source IP(s): {ips}")

    # Destination IPs
    shared_dst = ind_a.get("destination_ips", set()) & ind_b.get("destination_ips", set())
    if shared_dst:
        score += SCORE_WEIGHTS["same_destination_ip"]
        ips = ", ".join(sorted(shared_dst))
        reasons.append(f"share destination IP(s): {ips}")

    # Users
    shared_users = ind_a.get("users", set()) & ind_b.get("users", set())
    if shared_users:
        score += SCORE_WEIGHTS["same_user"]
        u = ", ".join(sorted(shared_users))
        reasons.append(f"target user(s): {u}")

    # Hosts
    shared_hosts = ind_a.get("hosts", set()) & ind_b.get("hosts", set())
    if shared_hosts:
        score += SCORE_WEIGHTS["same_host"]
        h = ", ".join(sorted(shared_hosts))
        reasons.append(f"target host(s): {h}")

    # IOCs
    shared_iocs = ind_a.get("iocs", set()) & ind_b.get("iocs", set())
    if shared_iocs:
        score += SCORE_WEIGHTS["same_ioc"]
        i = ", ".join(sorted(shared_iocs))
        reasons.append(f"share indicator(s): {i}")

    # Related event types
    if event_type_a and event_type_b and _event_types_related(event_type_a, event_type_b):
        score += SCORE_WEIGHTS["related_event_type"]
        reasons.append(f"related event types ({event_type_a}, {event_type_b})")

    # Time proximity
    if time_a is not None and time_b is not None:
        time_score = _time_proximity_score(time_a, time_b, time_window_minutes)
        if time_score > 0:
            score += time_score * SCORE_WEIGHTS["time_proximity"]
            delta = abs((time_a - time_b).total_seconds())
            if delta < 60:
                reasons.append(f"occurred within {int(delta)} seconds")
            else:
                reasons.append(f"occurred within {int(delta / 60)} minutes")

    return round(min(max(score, 0.0), 1.0), 4), reasons


def _time_proximity_score(
    t1: datetime, t2: datetime, window_minutes: int
) -> float:
    """Linear decay from 1.0 (same time) to 0.0 (outside window)."""
    if t1.tzinfo is None:
        t1 = t1.replace(tzinfo=None)
    if t2.tzinfo is None:
        t2 = t2.replace(tzinfo=None)
    delta = abs((t1 - t2).total_seconds())
    window_seconds = window_minutes * 60
    if delta > window_seconds:
        return 0.0
    return 1.0 - (delta / window_seconds)


def _event_types_related(type_a: str, type_b: str) -> bool:
    """Two event types are related if they appear in the same attack-stage group."""
    if type_a == type_b:
        return True
    for group in RELATED_EVENT_GROUPS:
        if type_a in group and type_b in group:
            return True
    return False


def max_severity(severities) -> str:
    """Return the highest severity from a collection."""
    best = "info"
    for s in severities:
        if SEVERITY_ORDER.get(s, 0) > SEVERITY_ORDER.get(best, 0):
            best = s
    return best
