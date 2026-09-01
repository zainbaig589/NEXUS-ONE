"""Tests for rule and alert API endpoints."""


def _create_rule(client, name="Test Rule", conditions=None, severity="high"):
    if conditions is None:
        conditions = {"type": "pattern_match", "field": "event_type", "pattern": "failed_login"}
    return client.post(
        "/api/v1/rules/",
        json={
            "name": name,
            "rule_type": "pattern_match",
            "severity": severity,
            "conditions": conditions,
        },
    )


class TestRulesAPI:
    def test_create_rule(self, client):
        response = _create_rule(client)
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Test Rule"
        assert data["enabled"] is True

    def test_create_duplicate_rule_name_rejected(self, client):
        _create_rule(client, name="Duplicate")
        response = _create_rule(client, name="Duplicate")
        assert response.status_code == 400

    def test_list_rules(self, client):
        _create_rule(client, name="Rule 1")
        _create_rule(client, name="Rule 2")
        response = client.get("/api/v1/rules/")
        assert response.status_code == 200
        assert len(response.json()) == 2

    def test_list_rules_enabled_only(self, client):
        _create_rule(client, name="Enabled")
        r2 = _create_rule(client, name="Disabled")
        client.patch(f"/api/v1/rules/{r2.json()['id']}/toggle?enabled=false")

        response = client.get("/api/v1/rules/?enabled_only=true")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["name"] == "Enabled"

    def test_get_rule(self, client):
        created = _create_rule(client)
        rule_id = created.json()["id"]
        response = client.get(f"/api/v1/rules/{rule_id}")
        assert response.status_code == 200
        assert response.json()["id"] == rule_id

    def test_get_nonexistent_rule(self, client):
        response = client.get("/api/v1/rules/nonexistent-id")
        assert response.status_code == 404

    def test_update_rule(self, client):
        created = _create_rule(client)
        rule_id = created.json()["id"]
        response = client.put(
            f"/api/v1/rules/{rule_id}",
            json={
                "name": "Updated Rule",
                "rule_type": "threshold",
                "severity": "critical",
                "conditions": {"type": "threshold", "field": "payload.x", "operator": "gt", "value": 10},
            },
        )
        assert response.status_code == 200
        assert response.json()["name"] == "Updated Rule"
        assert response.json()["severity"] == "critical"

    def test_delete_rule(self, client):
        created = _create_rule(client)
        rule_id = created.json()["id"]
        response = client.delete(f"/api/v1/rules/{rule_id}")
        assert response.status_code == 204
        assert client.get(f"/api/v1/rules/{rule_id}").status_code == 404

    def test_toggle_rule(self, client):
        created = _create_rule(client)
        rule_id = created.json()["id"]

        # Disable
        response = client.patch(f"/api/v1/rules/{rule_id}/toggle?enabled=false")
        assert response.status_code == 200
        assert response.json()["enabled"] is False

        # Re-enable
        response = client.patch(f"/api/v1/rules/{rule_id}/toggle?enabled=true")
        assert response.status_code == 200
        assert response.json()["enabled"] is True


class TestAlertsAPI:
    def _setup_rule_and_trigger(self, client):
        """Create a rule and trigger it by sending a matching event."""
        _create_rule(client, name="Alert Rule")
        event_response = client.post(
            "/api/v1/events/",
            json={
                "source": "auth",
                "event_type": "failed_login",
                "severity": "medium",
                "payload": {"user": "admin"},
            },
        )
        return event_response.json()["id"]

    def test_list_alerts(self, client):
        self._setup_rule_and_trigger(client)
        response = client.get("/api/v1/alerts/")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert any(alert["rule_name"] == "Alert Rule" for alert in data)

    def test_get_alert(self, client):
        self._setup_rule_and_trigger(client)
        alerts = client.get("/api/v1/alerts/").json()
        assert len(alerts) > 0
        alert_id = alerts[0]["id"]

        response = client.get(f"/api/v1/alerts/{alert_id}")
        assert response.status_code == 200
        assert response.json()["id"] == alert_id

    def test_update_alert_status(self, client):
        self._setup_rule_and_trigger(client)
        alerts = client.get("/api/v1/alerts/").json()
        alert_id = alerts[0]["id"]

        response = client.patch(f"/api/v1/alerts/{alert_id}/status?status=investigating")
        assert response.status_code == 200
        assert response.json()["status"] == "investigating"

    def test_filter_alerts_by_severity(self, client):
        _create_rule(client, name="High Rule", severity="high")
        _create_rule(client, name="Critical Rule", severity="critical")

        # Trigger both rules
        client.post(
            "/api/v1/events/",
            json={"source": "a", "event_type": "failed_login", "severity": "low", "payload": {}},
        )

        response = client.get("/api/v1/alerts/?severity=critical")
        assert response.status_code == 200
        for alert in response.json():
            assert alert["severity"] == "critical"


class TestDetectionIntegration:
    def test_event_creation_triggers_detection(self, client):
        """Creating an event via POST automatically runs detection."""
        _create_rule(client, name="Auto Detect")

        # Send matching event
        event_resp = client.post(
            "/api/v1/events/",
            json={
                "source": "firewall",
                "event_type": "failed_login",
                "severity": "medium",
                "payload": {"ip": "1.2.3.4"},
            },
        )
        assert event_resp.status_code == 201
        event_data = event_resp.json()
        assert event_data["processed"] is True

        # Verify alert was created
        alerts = client.get("/api/v1/alerts/").json()
        assert any(a["rule_name"] == "Auto Detect" for a in alerts)

    def test_non_matching_event_no_alert(self, client):
        _create_rule(client, name="Specific Rule")

        # Send non-matching event
        event_resp = client.post(
            "/api/v1/events/",
            json={
                "source": "app",
                "event_type": "page_view",
                "severity": "info",
                "payload": {},
            },
        )
        assert event_resp.status_code == 201
        assert event_resp.json()["processed"] is True

        # No alerts should be created
        alerts = client.get("/api/v1/alerts/").json()
        assert not any(a["rule_name"] == "Specific Rule" for a in alerts)

    def test_combination_rule(self, client):
        conditions = {
            "type": "combination",
            "logic": "and",
            "conditions": [
                {"type": "pattern_match", "field": "event_type", "pattern": "failed_login"},
                {"type": "threshold", "field": "payload.attempts", "operator": "gte", "value": 5},
            ],
        }
        _create_rule(client, name="Brute Force", conditions=conditions, severity="critical")

        # Below threshold - should NOT trigger
        client.post(
            "/api/v1/events/",
            json={"source": "auth", "event_type": "failed_login", "severity": "low", "payload": {"attempts": 2}},
        )
        alerts = client.get("/api/v1/alerts/").json()
        assert not any(a["rule_name"] == "Brute Force" for a in alerts)

        # At threshold - should trigger
        client.post(
            "/api/v1/events/",
            json={"source": "auth", "event_type": "failed_login", "severity": "low", "payload": {"attempts": 5}},
        )
        alerts = client.get("/api/v1/alerts/").json()
        assert any(a["rule_name"] == "Brute Force" for a in alerts)

    def test_process_unprocessed_endpoint(self, client):
        """Test the manual process endpoint for backlog processing."""
        _create_rule(client, name="Backlog Rule")

        # Create a rule, then process endpoint should handle any unprocessed events
        response = client.post("/api/v1/detection/process?limit=100")
        assert response.status_code == 200
        data = response.json()
        assert "processed_count" in data
        assert "alerts_created" in data
