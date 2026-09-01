"""Deterministic normalization for incoming security events."""

import ipaddress
from datetime import timezone
from typing import Any, Dict

from app.schemas import EventCreate


_PAYLOAD_ALIASES = {
    "src_ip": (
        "src_ip",
        "source_ip",
        "source_address",
        "source_addr",
        "client_ip",
        "remote_ip",
        "attacker_ip",
    ),
    "dst_ip": (
        "dst_ip",
        "dest_ip",
        "destination_ip",
        "destination_address",
        "destination_addr",
        "target_ip",
        "server_ip",
    ),
    "user": ("user", "username", "user_name", "account", "login", "uid", "subject"),
    "host": ("host", "hostname", "device", "machine", "computer", "endpoint"),
}

_ALIAS_TO_CANONICAL = {
    alias: canonical
    for canonical, aliases in _PAYLOAD_ALIASES.items()
    for alias in aliases
}


def normalize_event_data(event_data: EventCreate) -> Dict[str, Any]:
    """Return canonical, persistence-ready event data."""
    normalized = event_data.model_dump(exclude_none=True)
    normalized["source"] = normalized["source"].strip()
    normalized["event_type"] = _normalize_event_type(normalized["event_type"])
    normalized["severity"] = normalized["severity"].strip().lower()
    normalized["payload"] = _normalize_payload(normalized["payload"])

    timestamp = normalized.get("timestamp")
    if timestamp is not None:
        normalized["timestamp"] = (
            timestamp.replace(tzinfo=timezone.utc)
            if timestamp.tzinfo is None
            else timestamp.astimezone(timezone.utc)
        )

    return normalized


def _normalize_event_type(value: str) -> str:
    return "_".join(value.strip().lower().replace("-", " ").split())


def _normalize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    known_items = []
    unknown_payload = {}

    for key, value in payload.items():
        if _is_empty(value):
            continue
        key_lower = key.strip().lower()
        if key_lower in _ALIAS_TO_CANONICAL:
            known_items.append((key_lower, value))
        else:
            unknown_payload[key] = value

    canonical_payload = dict(unknown_payload)
    for canonical_key, aliases in _PAYLOAD_ALIASES.items():
        value = _select_alias_value(known_items, aliases)
        if value is None:
            continue
        if canonical_key in {"src_ip", "dst_ip"}:
            canonical_payload[canonical_key] = _normalize_ip(value)
        else:
            canonical_payload[canonical_key] = _normalize_identifier(value)

    return canonical_payload


def _is_empty(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _select_alias_value(known_items, aliases):
    for alias in aliases:
        for key, value in known_items:
            if key == alias:
                return value
    return None


def _normalize_ip(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    try:
        return str(ipaddress.ip_address(stripped))
    except ValueError:
        return stripped


def _normalize_identifier(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    return " ".join(value.strip().lower().split())
