"""Synthetic dataset generator for Isolation Forest training."""

from datetime import datetime, timezone
from typing import Tuple

import numpy as np
from app.ml.features import extract_features

_RNG = np.random.default_rng(42)


def _ts(hour: int) -> datetime:
    return datetime(2024, 1, 15, hour, 0, 0, tzinfo=timezone.utc)


def _normal_samples() -> np.ndarray:
    rows = []

    for _ in range(80):
        hour = int(_RNG.integers(8, 18))
        failed = int(_RNG.integers(0, 3))
        rows.append(extract_features(
            source="workstation",
            event_type="login",
            severity="info",
            payload={"failed_attempts": failed, "user": "alice", "host": "ws-01"},
            timestamp=_ts(hour),
        ))

    for _ in range(60):
        hour = int(_RNG.integers(8, 18))
        kb = int(_RNG.integers(100, 5000))
        rows.append(extract_features(
            source="firewall",
            event_type="network",
            severity="info",
            payload={"bytes_transferred": kb * 1024, "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8"},
            timestamp=_ts(hour),
        ))

    for _ in range(40):
        hour = int(_RNG.integers(9, 17))
        rows.append(extract_features(
            source="server",
            event_type="file_access",
            severity="low",
            payload={"user": "bob", "host": "srv-01", "path": "/etc/app.conf"},
            timestamp=_ts(hour),
        ))

    for _ in range(30):
        hour = int(_RNG.integers(8, 17))
        rows.append(extract_features(
            source="vpn",
            event_type="authentication",
            severity="info",
            payload={"user": "charlie", "src_ip": "192.168.1.10"},
            timestamp=_ts(hour),
        ))

    return np.array(rows, dtype=np.float32)


def _anomalous_samples() -> np.ndarray:
    rows = []

    for _ in range(15):
        hour = int(_RNG.choice([2, 3, 4, 23]))
        rows.append(extract_features(
            source="workstation",
            event_type="login",
            severity="medium",
            payload={"user": "eve", "host": "ws-99", "failed_attempts": 0},
            timestamp=_ts(hour),
        ))

    for _ in range(15):
        rows.append(extract_features(
            source="workstation",
            event_type="authentication",
            severity="high",
            payload={"failed_attempts": int(_RNG.integers(500, 2000)), "user": "mallory"},
            timestamp=_ts(int(_RNG.integers(8, 18))),
        ))

    for _ in range(10):
        gb = int(_RNG.integers(500, 2000))
        rows.append(extract_features(
            source="server",
            event_type="data_exfiltration",
            severity="critical",
            payload={
                "bytes_transferred": gb * 1024 * 1024,
                "dst_ip": "203.0.113.50",
                "src_ip": "10.0.0.5",
            },
            timestamp=_ts(int(_RNG.integers(1, 5))),
        ))

    for _ in range(10):
        rows.append(extract_features(
            source="ids",
            event_type="scan",
            severity="high",
            payload={
                "bytes_transferred": 0,
                "src_ip": "198.51.100.1",
                "dst_ip": "10.0.0.0/24",
                "failed_attempts": int(_RNG.integers(200, 1000)),
            },
            timestamp=_ts(int(_RNG.integers(0, 23))),
        ))

    return np.array(rows, dtype=np.float32)


def build_training_data() -> Tuple[np.ndarray, np.ndarray]:
    """Return (X, y) where y=0 normal, y=1 anomalous."""
    normal = _normal_samples()
    anomalous = _anomalous_samples()
    X = np.vstack([normal, anomalous])
    y = np.concatenate([np.zeros(len(normal)), np.ones(len(anomalous))])
    return X, y
