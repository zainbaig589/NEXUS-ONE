"""Deterministic attack-stage classification inspired by MITRE ATT&CK.

This module maps event types and rule names to potential kill-chain stages.
It is intentionally conservative: when evidence is insufficient it returns
"Potential stage: X" wording rather than claiming certainty.
"""

from typing import Dict, List, Optional, Set, Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Mapping from event_type to a MITRE ATT&CK-inspired stage.
# Unknown event types are handled safely (no stage assigned).
EVENT_TYPE_TO_STAGE: Dict[str, str] = {
    "failed_login": "Credential Access",
    "successful_login": "Initial Access",
    "account_lockout": "Credential Access",
    "privilege_escalation": "Privilege Escalation",
    "process_execution": "Execution",
    "malware_detected": "Execution",
    "registry_modification": "Persistence",
    "file_download": "Command and Control",
    "connection": "Command and Control",
    "dns_query": "Command and Control",
    "network_scan": "Discovery",
    "data_transfer": "Exfiltration",
    "lateral_movement": "Lateral Movement",
    "file_access": "Discovery",
    "login": "Initial Access",
    "logout": "Initial Access",
    "authentication": "Credential Access",
    "data_exfiltration": "Exfiltration",
    "scan": "Discovery",
}

# Fallback keyword mapping for rule names / descriptions when event_type is absent.
RULE_KEYWORDS_TO_STAGE: Dict[str, str] = {
    "brute": "Credential Access",
    "bruteforce": "Credential Access",
    "failed_login": "Credential Access",
    "privilege_escalation": "Privilege Escalation",
    "privilege escalation": "Privilege Escalation",
    "privesc": "Privilege Escalation",
    "escalation": "Privilege Escalation",
    "malware": "Execution",
    "ransomware": "Execution",
    "trojan": "Execution",
    "registry": "Persistence",
    "persistence": "Persistence",
    "lateral": "Lateral Movement",
    "exfil": "Exfiltration",
    "data_transfer": "Exfiltration",
    "scan": "Discovery",
    "recon": "Discovery",
    "discovery": "Discovery",
    "c2": "Command and Control",
    "command_and_control": "Command and Control",
    "dns": "Command and Control",
}

# Canonical ordering used when reporting progression (earlier -> later).
STAGE_ORDER: Dict[str, int] = {
    "Initial Access": 1,
    "Execution": 2,
    "Persistence": 3,
    "Privilege Escalation": 4,
    "Credential Access": 5,
    "Discovery": 6,
    "Lateral Movement": 7,
    "Command and Control": 8,
    "Exfiltration": 9,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify_event_type(event_type: Optional[str]) -> Optional[str]:
    """Return the potential attack stage for an event type, if known."""
    if not event_type:
        return None
    return EVENT_TYPE_TO_STAGE.get(event_type.lower())


def classify_rule_name(rule_name: Optional[str]) -> Optional[str]:
    """Return the potential attack stage implied by a rule name, if known."""
    if not rule_name:
        return None
    lower = rule_name.lower()
    for keyword, stage in RULE_KEYWORDS_TO_STAGE.items():
        if keyword in lower:
            return stage
    return None


def classify_event(event: Any) -> Optional[str]:
    """Classify a single event/alert-like object.

    Accepts either an Event model, an Alert model, or a simple object with
    `event_type` and/or `rule_name` attributes.
    """
    event_type = getattr(event, "event_type", None)
    rule_name = getattr(event, "rule_name", None)

    stage = classify_event_type(event_type)
    if stage:
        return stage
    return classify_rule_name(rule_name)


def classify_incident(alerts_or_events: List[Any]) -> List[str]:
    """Return the distinct potential attack stages for a collection of alerts/events.

    Stages are sorted by kill-chain progression and prefixed with
    "Potential stage: " to avoid implying confirmation.
    """
    raw_stages: Set[str] = set()
    for item in alerts_or_events:
        stage = classify_event(item)
        if stage:
            raw_stages.add(stage)

    sorted_stages = sorted(raw_stages, key=lambda s: STAGE_ORDER.get(s, 99))
    return [f"Potential stage: {stage}" for stage in sorted_stages]


def get_distinct_stages(alerts_or_events: List[Any]) -> List[str]:
    """Return plain stage names (no prefix) sorted by progression."""
    raw_stages: Set[str] = set()
    for item in alerts_or_events:
        stage = classify_event(item)
        if stage:
            raw_stages.add(stage)
    return sorted(raw_stages, key=lambda s: STAGE_ORDER.get(s, 99))
