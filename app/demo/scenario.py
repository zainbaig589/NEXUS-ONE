"""Canonical multi-stage attack scenario for demos.

SSH brute force -> successful login -> privilege escalation -> data exfiltration.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List


def build_attack_scenario_events(demo_run_id: str) -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc)

    def at(minutes_offset: int) -> str:
        return (now + timedelta(minutes=minutes_offset)).isoformat()

    base = {
        "src_ip": "185.220.101.5",
        "user": "admin",
        "host": "ws-042",
        "_demo_run_id": demo_run_id,
    }

    return [
        {
            "source": "auth-service",
            "event_type": "failed_login",
            "severity": "high",
            "timestamp": at(0),
            "payload": {
                **base,
                "failed_attempts": 6,
                "action": "ssh_login",
                "outcome": "failure",
            },
        },
        {
            "source": "auth-service",
            "event_type": "failed_login",
            "severity": "high",
            "timestamp": at(2),
            "payload": {
                **base,
                "failed_attempts": 9,
                "action": "ssh_login",
                "outcome": "failure",
            },
        },
        {
            "source": "auth-service",
            "event_type": "failed_login",
            "severity": "high",
            "timestamp": at(4),
            "payload": {
                **base,
                "failed_attempts": 11,
                "action": "ssh_login",
                "outcome": "failure",
            },
        },
        {
            "source": "auth-service",
            "event_type": "successful_login",
            "severity": "medium",
            "timestamp": at(5),
            "payload": {
                **base,
                "action": "ssh_login",
                "outcome": "success",
            },
        },
        {
            "source": "iam",
            "event_type": "privilege_escalation",
            "severity": "critical",
            "timestamp": at(7),
            "payload": {
                **base,
                "old_role": "viewer",
                "new_role": "root",
                "method": "sudo",
            },
        },
        {
            "source": "netflow",
            "event_type": "data_transfer",
            "severity": "critical",
            "timestamp": at(12),
            "payload": {
                **base,
                "dst_ip": "198.51.100.7",
                "bytes_transferred": 2_147_483_648,
                "protocol": "https",
            },
        },
    ]
