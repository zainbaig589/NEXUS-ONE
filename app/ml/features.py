"""Feature extraction for ML anomaly detection."""

from datetime import datetime, timezone
from typing import Dict, Any, List

import numpy as np

SEVERITY_MAP = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

EVENT_TYPE_MAP = {
    "login": 0, "logout": 1, "file_access": 2, "network": 3,
    "process": 4, "authentication": 5, "privilege_escalation": 6,
    "data_exfiltration": 7, "malware": 8, "scan": 9,
}

FEATURE_NAMES = [
    "severity_score",
    "event_type_score",
    "failed_attempts",
    "bytes_transferred_log",
    "hour_of_day",
    "is_off_hours",
    "has_src_ip",
    "has_dst_ip",
    "has_user",
    "has_host",
    "payload_size",
]


def extract_features(
    source: str,
    event_type: str,
    severity: str,
    payload: Dict[str, Any],
    timestamp: datetime = None,
) -> np.ndarray:
    """Return a 1-D float32 feature vector for one event."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    hour = timestamp.hour if timestamp else 12

    severity_score = float(SEVERITY_MAP.get(severity.lower(), 2))

    et_lower = event_type.lower()
    et_score = float(next(
        (v for k, v in EVENT_TYPE_MAP.items() if k in et_lower),
        5.0,
    ))

    failed_attempts = float(payload.get("failed_attempts", 0) or 0)
    bytes_transferred = float(payload.get("bytes_transferred", 0) or 0)
    bytes_log = float(np.log1p(bytes_transferred))

    is_off_hours = float(hour < 6 or hour > 22)
    has_src_ip = float(bool(payload.get("src_ip") or payload.get("source_ip")))
    has_dst_ip = float(bool(payload.get("dst_ip") or payload.get("destination_ip")))
    has_user = float(bool(payload.get("user") or payload.get("username")))
    has_host = float(bool(payload.get("host") or payload.get("hostname")))
    payload_size = float(len(payload))

    return np.array([
        severity_score,
        et_score,
        failed_attempts,
        bytes_log,
        float(hour),
        is_off_hours,
        has_src_ip,
        has_dst_ip,
        has_user,
        has_host,
        payload_size,
    ], dtype=np.float32)


def feature_names() -> List[str]:
    return list(FEATURE_NAMES)
