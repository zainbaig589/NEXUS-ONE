"""Model and schema tests."""

import pytest


@pytest.fixture
def sample_event():
    return {
        "source": "firewall",
        "event_type": "connection_blocked",
        "severity": "medium",
        "payload": {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1"},
    }


def test_event_creation(client, sample_event):
    response = client.post("/api/v1/events/", json=sample_event)
    assert response.status_code == 201
    data = response.json()
    assert data["source"] == sample_event["source"]
    # Event is auto-processed through the detection engine on creation
    assert data["processed"] is True


def test_event_validation_invalid_severity(client):
    invalid_event = {
        "source": "test",
        "event_type": "test",
        "severity": "invalid",
        "payload": {},
    }
    response = client.post("/api/v1/events/", json=invalid_event)
    assert response.status_code == 422
