"""Regression coverage for ML alert ingestion."""

from unittest.mock import patch

from app.models.alert import Alert
from app.models.event import Event
from app.models.rule import Rule
from app.services import DetectionService


def _ml_result(*, is_anomaly=True, severity="critical"):
    return {
        "anomaly_score": 0.9 if is_anomaly else 0.1,
        "is_anomaly": is_anomaly,
        "confidence": 0.9,
        "severity": severity,
        "reason": "Anomaly detected: deterministic test signal",
        "features_used": [],
        "detection_method": "isolation_forest",
    }


def _create_rule(client, name, pattern, severity="high"):
    return client.post(
        "/api/v1/rules/",
        json={
            "name": name,
            "rule_type": "pattern_match",
            "severity": severity,
            "conditions": {
                "type": "pattern_match",
                "field": "event_type",
                "pattern": pattern,
            },
        },
    )


def test_normal_ml_result_creates_no_alert(client):
    with patch(
        "app.detection.MLService.analyze",
        return_value=_ml_result(is_anomaly=False, severity="info"),
    ):
        response = client.post(
            "/api/v1/events/",
            json={
                "source": "workstation",
                "event_type": "login",
                "severity": "info",
                "payload": {"user": "alice"},
            },
        )

    assert response.status_code == 201
    assert client.get("/api/v1/alerts/").json() == []


def test_anomalous_ml_result_creates_one_idempotent_alert(client, db_session):
    with patch("app.detection.MLService.analyze", return_value=_ml_result()):
        response = client.post(
            "/api/v1/events/",
            json={
                "source": "workstation",
                "event_type": "authentication",
                "severity": "high",
                "payload": {"failed_attempts": 800, "user": "mallory"},
            },
        )
        assert response.status_code == 201
        event = db_session.query(Event).filter(Event.id == response.json()["id"]).one()
        DetectionService.process_event(db_session, event)

    ml_alerts = db_session.query(Alert).filter(Alert.detection_source == "ml").all()
    assert len(ml_alerts) == 1
    assert ml_alerts[0].severity == "medium"
    assert ml_alerts[0].description == "Anomaly detected: deterministic test signal"
    sentinel = db_session.query(Rule).filter(Rule.name == "ML Anomaly Detection").one()
    assert sentinel.enabled is False


def test_ml_and_rule_alerts_correlate_with_ml_timeline_entry(client):
    assert _create_rule(client, "Authentication Rule", "authentication").status_code == 201

    with patch("app.detection.MLService.analyze", return_value=_ml_result()):
        response = client.post(
            "/api/v1/events/",
            json={
                "source": "workstation",
                "event_type": "authentication",
                "severity": "high",
                "payload": {
                    "src_ip": "198.51.100.40",
                    "user": "mallory",
                    "host": "ws-40",
                    "failed_attempts": 800,
                },
            },
        )

    assert response.status_code == 201
    correlation = client.post("/api/v1/incidents/correlate")
    assert correlation.status_code == 200
    incident_id = correlation.json()["incident_ids"][0]

    alerts = client.get(f"/api/v1/incidents/{incident_id}/alerts").json()
    assert {alert["detection_source"] for alert in alerts} == {"rule", "ml"}
    assert client.get(f"/api/v1/incidents/{incident_id}").json()["severity"] == "high"

    timeline = client.get(f"/api/v1/incidents/{incident_id}/timeline").json()
    assert {entry["detection_method"] for entry in timeline["entries"]} == {"rule", "ml"}


def test_ml_only_alert_cannot_create_high_or_critical_incident(client):
    with patch("app.detection.MLService.analyze", return_value=_ml_result(severity="critical")):
        response = client.post(
            "/api/v1/events/",
            json={
                "source": "server",
                "event_type": "data_exfiltration",
                "severity": "critical",
                "payload": {"bytes_transferred": 1024 * 1024 * 1024},
            },
        )

    assert response.status_code == 201
    alerts = client.get("/api/v1/alerts/").json()
    assert [(alert["detection_source"], alert["severity"]) for alert in alerts] == [("ml", "medium")]

    correlation = client.post("/api/v1/incidents/correlate")
    assert correlation.status_code == 200
    incident = client.get(f"/api/v1/incidents/{correlation.json()['incident_ids'][0]}").json()
    assert incident["severity"] == "medium"


def test_ml_inference_failure_does_not_block_rule_detection(client):
    assert _create_rule(client, "Fallback Rule", "failed_login").status_code == 201

    with patch("app.detection.MLService.analyze", side_effect=RuntimeError("unavailable")):
        response = client.post(
            "/api/v1/events/",
            json={
                "source": "auth",
                "event_type": "failed_login",
                "severity": "medium",
                "payload": {},
            },
        )

    assert response.status_code == 201
    alerts = client.get("/api/v1/alerts/").json()
    assert [(alert["rule_name"], alert["detection_source"]) for alert in alerts] == [
        ("Fallback Rule", "rule")
    ]
