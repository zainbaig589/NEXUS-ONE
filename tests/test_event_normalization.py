"""Regression coverage for event normalization."""

from datetime import datetime, timezone
from unittest.mock import patch

from app.schemas import EventCreate
from app.services.event_normalizer import normalize_event_data


def test_normalization_is_canonical_and_idempotent():
    event = EventCreate(
        source=" firewall ",
        event_type=" Failed-Login ",
        severity=" HIGH ",
        timestamp="2024-06-15T03:00:00-05:00",
        payload={
            "Source_IP": " 2001:0db8:0000:0000:0000:0000:0000:0001 ",
            "Destination_IP": " 192.168.1.9 ",
            "Username": " Alice Smith ",
            "Hostname": " DC-01 ",
            "empty_value": "   ",
            "none_value": None,
            "unknown_field": " Preserve This Value ",
        },
    )

    normalized = normalize_event_data(event)

    assert normalized["source"] == "firewall"
    assert normalized["event_type"] == "failed_login"
    assert normalized["severity"] == "high"
    assert normalized["timestamp"] == datetime(2024, 6, 15, 8, 0, tzinfo=timezone.utc)
    assert normalized["payload"] == {
        "unknown_field": " Preserve This Value ",
        "src_ip": "2001:db8::1",
        "dst_ip": "192.168.1.9",
        "user": "alice smith",
        "host": "dc-01",
    }
    assert normalize_event_data(EventCreate(**normalized)) == normalized


def test_event_api_persists_normalized_rule_compatible_event(client):
    rule_response = client.post(
        "/api/v1/rules/",
        json={
            "name": "Normalized Login",
            "rule_type": "pattern_match",
            "severity": "high",
            "conditions": {
                "type": "pattern_match",
                "field": "event_type",
                "pattern": "failed_login",
            },
        },
    )
    assert rule_response.status_code == 201

    with patch(
        "app.detection.MLService.analyze",
        return_value={"is_anomaly": False},
    ):
        response = client.post(
            "/api/v1/events/",
            json={
                "source": " auth ",
                "event_type": " Failed Login ",
                "severity": " MEDIUM ",
                "timestamp": "2024-01-15T03:00:00-05:00",
                "payload": {
                    "remote_ip": " 203.0.113.7 ",
                    "username": " Admin ",
                    "hostname": " DC-01 ",
                    "empty": "",
                    "custom": {"unchanged": True},
                },
            },
        )

    assert response.status_code == 201
    data = response.json()
    assert data["event_type"] == "failed_login"
    assert data["severity"] == "medium"
    assert data["payload"] == {
        "src_ip": "203.0.113.7",
        "user": "admin",
        "host": "dc-01",
        "custom": {"unchanged": True},
    }
    assert datetime.fromisoformat(data["timestamp"]).replace(tzinfo=timezone.utc) == datetime(
        2024, 1, 15, 8, 0, tzinfo=timezone.utc
    )

    alerts = client.get("/api/v1/alerts/").json()
    assert [(alert["rule_name"], alert["detection_source"]) for alert in alerts] == [
        ("Normalized Login", "rule")
    ]
