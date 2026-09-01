"""Tests for risk scoring, attack timeline, and attack-stage classification."""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Incident
from app.models.rule import Rule
from app.correlation import CorrelationEngine
from app.risk.scorer import calculate_risk, risk_level_from_score, RISK_LEVELS
from app.timeline import build_timeline
from app.attack_stages import classify_event_type, classify_incident


def _make_alert(
    db_session,
    *,
    rule_name,
    severity="high",
    event_type="test_event",
    payload=None,
    timestamp=None,
):
    """Create a Rule + Event + Alert in the test DB. Returns the alert."""
    rule = db_session.query(Rule).filter(Rule.name == rule_name).first()
    if not rule:
        rule = Rule(
            name=rule_name,
            rule_type="pattern_match",
            severity=severity,
            conditions={"type": "pattern_match", "field": "event_type", "pattern": event_type},
            enabled=True,
        )
        db_session.add(rule)
        db_session.flush()

    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    event = Event(
        source="test",
        event_type=event_type,
        severity=severity,
        payload=payload or {},
        timestamp=timestamp,
    )
    db_session.add(event)
    db_session.flush()

    alert = Alert(
        event_id=event.id,
        rule_id=rule.id,
        rule_name=rule_name,
        severity=severity,
        status="new",
    )
    db_session.add(alert)
    db_session.flush()
    return alert


class TestRiskLevels:
    def test_low_risk_single_info_alert(self, db_session):
        a1 = _make_alert(db_session, rule_name="Info Rule", severity="info", event_type="login")
        db_session.commit()

        engine = CorrelationEngine(db_session)
        incidents = engine.correlate()

        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.risk_level == "LOW"
        assert 0 <= inc.risk_score <= 25

    def test_medium_risk_multiple_medium_alerts(self, db_session):
        now = datetime.now(timezone.utc)
        _make_alert(
            db_session,
            rule_name="Medium A",
            severity="medium",
            event_type="network_scan",
            payload={"host": "WS-01"},
            timestamp=now,
        )
        _make_alert(
            db_session,
            rule_name="Medium B",
            severity="medium",
            event_type="connection",
            payload={"host": "WS-01"},
            timestamp=now + timedelta(minutes=2),
        )
        db_session.commit()

        engine = CorrelationEngine(db_session)
        incidents = engine.correlate()

        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.risk_level == "MEDIUM"
        assert 25 <= inc.risk_score <= 50

    def test_high_risk_multi_stage_attack(self, db_session):
        now = datetime.now(timezone.utc)
        _make_alert(
            db_session,
            rule_name="Brute Force",
            severity="high",
            event_type="failed_login",
            payload={"src_ip": "185.220.101.5", "user": "admin", "host": "DC-01"},
            timestamp=now,
        )
        _make_alert(
            db_session,
            rule_name="Privilege Escalation",
            severity="high",
            event_type="privilege_escalation",
            payload={"src_ip": "185.220.101.5", "user": "admin", "host": "DC-01"},
            timestamp=now + timedelta(minutes=2),
        )
        _make_alert(
            db_session,
            rule_name="Malware",
            severity="high",
            event_type="malware_detected",
            payload={"src_ip": "185.220.101.5", "host": "DC-01", "signature": "trojan.win32"},
            timestamp=now + timedelta(minutes=5),
        )
        _make_alert(
            db_session,
            rule_name="Exfiltration",
            severity="high",
            event_type="data_transfer",
            payload={"src_ip": "185.220.101.5", "dst_ip": "198.51.100.1", "bytes_transferred": 500000},
            timestamp=now + timedelta(minutes=8),
        )
        db_session.commit()

        engine = CorrelationEngine(db_session)
        incidents = engine.correlate()

        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.risk_level == "HIGH"
        assert 50 <= inc.risk_score <= 75

    def test_critical_risk_many_critical_alerts_with_anomaly(self, db_session):
        now = datetime.now(timezone.utc)
        for i in range(8):
            _make_alert(
                db_session,
                rule_name=f"Critical Rule {i}",
                severity="critical",
                event_type="data_exfiltration" if i % 2 == 0 else "privilege_escalation",
                payload={
                    "src_ip": f"10.0.0.{i + 1}",
                    "dst_ip": "203.0.113.1",
                    "user": f"user{i % 3}",
                    "host": f"HOST-{i % 3}",
                    "anomaly_score": 0.85,
                },
                timestamp=now + timedelta(minutes=i),
            )
        db_session.commit()

        engine = CorrelationEngine(db_session)
        incidents = engine.correlate()

        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.risk_level == "CRITICAL"
        assert 75 <= inc.risk_score <= 100

    def test_risk_score_is_within_bounds(self, db_session):
        now = datetime.now(timezone.utc)
        for i in range(20):
            _make_alert(
                db_session,
                rule_name=f"Rule {i}",
                severity="critical",
                event_type="malware_detected",
                payload={"host": "CRITICAL-HOST", "anomaly_score": 1.0},
                timestamp=now + timedelta(minutes=i),
            )
        db_session.commit()

        engine = CorrelationEngine(db_session)
        incidents = engine.correlate()

        assert len(incidents) == 1
        assert 0 <= incidents[0].risk_score <= 100

    def test_risk_calculation_is_deterministic(self, db_session):
        now = datetime.now(timezone.utc)
        _make_alert(
            db_session,
            rule_name="Det A",
            severity="high",
            event_type="failed_login",
            payload={"src_ip": "1.2.3.4"},
            timestamp=now,
        )
        _make_alert(
            db_session,
            rule_name="Det B",
            severity="high",
            event_type="privilege_escalation",
            payload={"src_ip": "1.2.3.4"},
            timestamp=now + timedelta(minutes=1),
        )
        db_session.commit()

        engine = CorrelationEngine(db_session)
        inc1 = engine.correlate()[0]
        db_session.refresh(inc1)

        # Recompute directly from the same stored data
        alerts = db_session.query(Alert).filter(Alert.id.in_(inc1.alert_ids)).all()
        events_by_alert = {a.id: a.event for a in alerts}
        result = calculate_risk(inc1, alerts, events_by_alert)

        assert result["risk_score"] == inc1.risk_score
        assert result["risk_level"] == inc1.risk_level


class TestRiskExplanation:
    def test_explanation_mentions_contributing_factors(self, db_session):
        now = datetime.now(timezone.utc)
        _make_alert(
            db_session,
            rule_name="Brute Force",
            severity="high",
            event_type="failed_login",
            payload={"src_ip": "185.220.101.5", "user": "admin", "host": "DC-01"},
            timestamp=now,
        )
        _make_alert(
            db_session,
            rule_name="Priv Esc",
            severity="high",
            event_type="privilege_escalation",
            payload={"src_ip": "185.220.101.5", "user": "admin", "host": "DC-01"},
            timestamp=now + timedelta(minutes=1),
        )
        db_session.commit()

        engine = CorrelationEngine(db_session)
        inc = engine.correlate()[0]

        explanation = " ".join(inc.risk_factors).lower()
        assert "correlated alert" in explanation
        assert "host" in explanation or "user" in explanation or "severity" in explanation

    def test_risk_level_from_score_thresholds(self):
        assert risk_level_from_score(10) == "LOW"
        assert risk_level_from_score(30) == "MEDIUM"
        assert risk_level_from_score(60) == "HIGH"
        assert risk_level_from_score(90) == "CRITICAL"


class TestTimeline:
    def test_timeline_is_chronologically_ordered(self, db_session):
        now = datetime.now(timezone.utc)
        a1 = _make_alert(
            db_session,
            rule_name="Late",
            event_type="data_transfer",
            payload={"src_ip": "10.0.0.5", "dst_ip": "198.51.100.1"},
            timestamp=now + timedelta(minutes=2),
        )
        a2 = _make_alert(
            db_session,
            rule_name="Early",
            event_type="failed_login",
            payload={"src_ip": "10.0.0.5", "dst_ip": "198.51.100.1"},
            timestamp=now,
        )
        db_session.commit()

        engine = CorrelationEngine(db_session)
        inc = engine.correlate()[0]

        timeline = build_timeline(inc, db_session.query(Alert).filter(Alert.id.in_(inc.alert_ids)).all())
        timestamps = [e["timestamp"] for e in timeline["entries"]]
        assert timestamps == sorted(timestamps)
        assert timeline["entries"][0]["event_type"] == "failed_login"

    def test_timeline_contains_all_alerts(self, db_session):
        now = datetime.now(timezone.utc)
        alerts = []
        for i, et in enumerate(["failed_login", "privilege_escalation", "malware_detected"]):
            alerts.append(
                _make_alert(
                    db_session,
                    rule_name=f"R{i}",
                    event_type=et,
                    payload={"src_ip": "10.0.0.5", "dst_ip": "198.51.100.1"},
                    timestamp=now + timedelta(minutes=i),
                )
            )
        db_session.commit()

        engine = CorrelationEngine(db_session)
        inc = engine.correlate()[0]

        timeline = build_timeline(inc, db_session.query(Alert).filter(Alert.id.in_(inc.alert_ids)).all())
        entry_alert_ids = {e["alert_id"] for e in timeline["entries"]}
        assert entry_alert_ids == set(inc.alert_ids)
        assert len(entry_alert_ids) == 3

    def test_timeline_first_and_last_timestamps(self, db_session):
        now = datetime.now(timezone.utc)
        _make_alert(
            db_session,
            rule_name="First",
            event_type="failed_login",
            payload={"src_ip": "10.0.0.5", "dst_ip": "198.51.100.1"},
            timestamp=now,
        )
        _make_alert(
            db_session,
            rule_name="Last",
            event_type="data_transfer",
            payload={"src_ip": "10.0.0.5", "dst_ip": "198.51.100.1"},
            timestamp=now + timedelta(minutes=10),
        )
        db_session.commit()

        engine = CorrelationEngine(db_session)
        inc = engine.correlate()[0]

        timeline = build_timeline(inc, db_session.query(Alert).filter(Alert.id.in_(inc.alert_ids)).all())
        assert timeline["first_seen"].replace(tzinfo=None) == now.replace(tzinfo=None)
        assert timeline["last_seen"].replace(tzinfo=None) == (now + timedelta(minutes=10)).replace(tzinfo=None)
        assert timeline["duration_seconds"] == 600

    def test_timeline_preserves_event_details(self, db_session):
        now = datetime.now(timezone.utc)
        _make_alert(
            db_session,
            rule_name="Detail Rule",
            severity="medium",
            event_type="failed_login",
            payload={"src_ip": "1.2.3.4", "user": "alice", "host": "WS-01"},
            timestamp=now,
        )
        db_session.commit()

        engine = CorrelationEngine(db_session)
        inc = engine.correlate()[0]

        timeline = build_timeline(inc, db_session.query(Alert).filter(Alert.id.in_(inc.alert_ids)).all())
        entry = timeline["entries"][0]
        assert entry["event_type"] == "failed_login"
        assert entry["source_ip"] == "1.2.3.4"
        assert entry["user"] == "alice"
        assert entry["host"] == "WS-01"
        assert entry["severity"] == "medium"
        assert entry["detection_method"] == "rule"


class TestAttackStages:
    def test_stage_mapping(self, db_session):
        now = datetime.now(timezone.utc)
        _make_alert(
            db_session,
            rule_name="Brute Force",
            event_type="failed_login",
            payload={"src_ip": "10.0.0.5", "dst_ip": "198.51.100.1", "user": "admin"},
            timestamp=now,
        )
        _make_alert(
            db_session,
            rule_name="Priv Esc",
            event_type="privilege_escalation",
            payload={"src_ip": "10.0.0.5", "dst_ip": "198.51.100.1", "user": "admin"},
            timestamp=now + timedelta(minutes=1),
        )
        _make_alert(
            db_session,
            rule_name="Malware",
            event_type="malware_detected",
            payload={"src_ip": "10.0.0.5", "dst_ip": "198.51.100.1", "host": "DC-01"},
            timestamp=now + timedelta(minutes=2),
        )
        _make_alert(
            db_session,
            rule_name="Exfil",
            event_type="data_transfer",
            payload={"src_ip": "10.0.0.5", "dst_ip": "198.51.100.1"},
            timestamp=now + timedelta(minutes=3),
        )
        db_session.commit()

        engine = CorrelationEngine(db_session)
        inc = engine.correlate()[0]

        assert "Potential stage: Credential Access" in inc.attack_stages
        assert "Potential stage: Privilege Escalation" in inc.attack_stages
        assert "Potential stage: Execution" in inc.attack_stages
        assert "Potential stage: Exfiltration" in inc.attack_stages
        # Stages should be ordered by progression
        assert inc.attack_stages.index("Potential stage: Credential Access") < inc.attack_stages.index("Potential stage: Exfiltration")

    def test_unknown_event_type_handled_safely(self, db_session):
        a1 = _make_alert(db_session, rule_name="Unknown Rule", event_type="unknown_type_xyz")
        db_session.commit()

        engine = CorrelationEngine(db_session)
        inc = engine.correlate()[0]

        assert inc.attack_stages == []
        assert classify_event_type("totally_unknown_event") is None
        assert classify_incident([a1]) == []


class TestRiskTimelineAPI:
    def test_get_risk_endpoint(self, client):
        client.post("/api/v1/rules/", json={
            "name": "RiskRule",
            "rule_type": "pattern_match",
            "severity": "high",
            "conditions": {"type": "pattern_match", "field": "event_type", "pattern": "risk_event"},
            "enabled": True,
        })
        client.post("/api/v1/events/", json={
            "source": "test",
            "event_type": "risk_event",
            "severity": "high",
            "payload": {"src_ip": "1.2.3.4"},
        })
        corr = client.post("/api/v1/incidents/correlate").json()
        inc_id = corr["incident_ids"][0]

        resp = client.get(f"/api/v1/incidents/{inc_id}/risk")
        assert resp.status_code == 200
        data = resp.json()
        assert "risk_score" in data
        assert "risk_level" in data
        assert "contributing_factors" in data
        assert "scoring_explanation" in data

    def test_get_timeline_endpoint(self, client):
        client.post("/api/v1/rules/", json={
            "name": "TimelineRule",
            "rule_type": "pattern_match",
            "severity": "medium",
            "conditions": {"type": "pattern_match", "field": "event_type", "pattern": "timeline_event"},
            "enabled": True,
        })
        client.post("/api/v1/events/", json={
            "source": "test",
            "event_type": "timeline_event",
            "severity": "medium",
            "payload": {"src_ip": "1.2.3.4"},
        })
        corr = client.post("/api/v1/incidents/correlate").json()
        inc_id = corr["incident_ids"][0]

        resp = client.get(f"/api/v1/incidents/{inc_id}/timeline")
        assert resp.status_code == 200
        data = resp.json()
        assert data["incident_id"] == inc_id
        assert "entries" in data
        assert "duration_seconds" in data

    def test_get_summary_endpoint(self, client):
        client.post("/api/v1/rules/", json={
            "name": "SummaryRule",
            "rule_type": "pattern_match",
            "severity": "high",
            "conditions": {"type": "pattern_match", "field": "event_type", "pattern": "summary_event"},
            "enabled": True,
        })
        client.post("/api/v1/events/", json={
            "source": "test",
            "event_type": "summary_event",
            "severity": "high",
            "payload": {"src_ip": "1.2.3.4", "host": "WS-01"},
        })
        corr = client.post("/api/v1/incidents/correlate").json()
        inc_id = corr["incident_ids"][0]

        resp = client.get(f"/api/v1/incidents/{inc_id}/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "incident" in data
        assert "risk" in data
        assert "timeline" in data
        assert "potential_attack_stages" in data
        assert "related_alert_ids" in data
        assert data["incident"]["id"] == inc_id
