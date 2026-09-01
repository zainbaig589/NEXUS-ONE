"""API endpoint tests."""


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app_name"] == "Nexus One"


def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["app_name"] == "Nexus One"
    assert data["version"] == "0.1.0"


def test_create_event(client):
    event_data = {
        "source": "firewall",
        "event_type": "connection_blocked",
        "severity": "medium",
        "payload": {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1"},
    }
    response = client.post("/api/v1/events/", json=event_data)
    assert response.status_code == 201
    data = response.json()
    assert data["source"] == "firewall"
    assert data["event_type"] == "connection_blocked"
    assert data["severity"] == "medium"
    assert "id" in data


def test_list_events(client):
    event_data = {
        "source": "ids",
        "event_type": "alert",
        "severity": "high",
        "payload": {"signature": "ET MALWARE Known Bad IP"},
    }
    client.post("/api/v1/events/", json=event_data)

    response = client.get("/api/v1/events/")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
