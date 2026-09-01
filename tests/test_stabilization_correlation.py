"""Regression coverage for correlation accounting and bounded scores."""

from datetime import datetime, timedelta, timezone

import pytest

from app.correlation import CorrelationEngine
from app.correlation.scorer import compute_score
from app.models.alert import Alert
from app.models.event import Event
from app.models.rule import Rule


def _create_alert(
    db_session,
    *,
    rule_name,
    event_type,
    payload,
    timestamp=None,
    severity="high",
):
    rule = db_session.query(Rule).filter(Rule.name == rule_name).first()
    if rule is None:
        rule = Rule(
            name=rule_name,
            rule_type="pattern_match",
            severity=severity,
            conditions={
                "type": "pattern_match",
                "field": "event_type",
                "pattern": event_type,
            },
            enabled=True,
        )
        db_session.add(rule)
        db_session.flush()

    event = Event(
        source="test",
        event_type=event_type,
        severity=severity,
        payload=payload,
        timestamp=timestamp or datetime.now(timezone.utc),
    )
    db_session.add(event)
    db_session.flush()

    alert = Alert(
        event_id=event.id,
        rule_id=rule.id,
        rule_name=rule.name,
        severity=severity,
        status="new",
    )
    db_session.add(alert)
    db_session.flush()
    return alert


def test_correlation_api_reports_same_run_incident_as_created(client, db_session):
    now = datetime.now(timezone.utc)
    _create_alert(
        db_session,
        rule_name="First",
        event_type="first_event",
        payload={"src_ip": "198.51.100.10"},
        timestamp=now,
    )
    _create_alert(
        db_session,
        rule_name="Second",
        event_type="second_event",
        payload={"src_ip": "198.51.100.10"},
        timestamp=now + timedelta(minutes=1),
    )
    db_session.commit()

    first_run = client.post("/api/v1/incidents/correlate")
    assert first_run.status_code == 200
    assert first_run.json() == {
        "incidents_touched": 1,
        "incidents_created": 1,
        "incidents_updated": 0,
        "incident_ids": first_run.json()["incident_ids"],
    }

    second_run = client.post("/api/v1/incidents/correlate")
    assert second_run.status_code == 200
    assert second_run.json() == {
        "incidents_touched": 0,
        "incidents_created": 0,
        "incidents_updated": 0,
        "incident_ids": [],
    }


def test_correlation_api_reports_mixed_created_and_updated_incidents(client, db_session):
    now = datetime.now(timezone.utc)
    _create_alert(
        db_session,
        rule_name="Seed",
        event_type="seed_event",
        payload={"src_ip": "198.51.100.11"},
        timestamp=now,
    )
    db_session.commit()
    client.post("/api/v1/incidents/correlate")

    _create_alert(
        db_session,
        rule_name="Follow Up",
        event_type="follow_up_event",
        payload={"src_ip": "198.51.100.11"},
        timestamp=now + timedelta(minutes=1),
    )
    _create_alert(
        db_session,
        rule_name="Unrelated",
        event_type="unrelated_event",
        payload={"src_ip": "203.0.113.11"},
        timestamp=now + timedelta(minutes=1),
    )
    db_session.commit()

    response = client.post("/api/v1/incidents/correlate")

    assert response.status_code == 200
    data = response.json()
    assert data["incidents_touched"] == 2
    assert data["incidents_created"] == 1
    assert data["incidents_updated"] == 1
    assert data["incidents_created"] + data["incidents_updated"] == data["incidents_touched"]


def test_scorer_clamps_all_matching_factors_to_one():
    indicators = {
        "source_ips": {"198.51.100.20"},
        "destination_ips": {"10.0.0.20"},
        "users": {"admin"},
        "hosts": {"dc-01"},
        "iocs": {"hash-abc"},
    }
    now = datetime.now(timezone.utc)

    score, reasons = compute_score(
        indicators,
        indicators,
        now,
        now,
        "failed_login",
        "privilege_escalation",
    )

    assert score == pytest.approx(1.0)
    assert len(reasons) == 7


def test_engine_never_persists_score_above_one(db_session):
    now = datetime.now(timezone.utc)
    shared_payload = {
        "src_ip": "198.51.100.30",
        "dst_ip": "10.0.0.30",
        "user": "admin",
        "host": "dc-01",
    }
    _create_alert(
        db_session,
        rule_name="Login",
        event_type="failed_login",
        payload=shared_payload,
        timestamp=now,
    )
    _create_alert(
        db_session,
        rule_name="Escalation",
        event_type="privilege_escalation",
        payload=shared_payload,
        timestamp=now + timedelta(seconds=1),
    )
    db_session.commit()

    incidents = CorrelationEngine(db_session).correlate()

    assert len(incidents) == 1
    assert incidents[0].correlation_score == pytest.approx(1.0)
