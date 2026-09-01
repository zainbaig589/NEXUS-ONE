"""Comprehensive tests for the correlation engine.

Covers:
    - Scorer unit tests
    - Engine unit tests (same IP, same user/host, unrelated, multi-stage, idempotency, score, evidence)
    - API endpoint tests
    - End-to-end realistic attack scenario
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Incident
from app.models.rule import Rule
from app.correlation.scorer import (
    extract_indicators,
    compute_score,
    max_severity,
    _time_proximity_score,
    _event_types_related,
    SCORE_WEIGHTS,
)
from app.correlation import CorrelationEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


# ===========================================================================
# Scorer unit tests
# ===========================================================================

class TestExtractIndicators:
    def test_extracts_source_ip(self):
        class _Ev:
            payload = {"src_ip": "1.2.3.4"}
            event_type = "x"
        ind = extract_indicators(_Ev())
        assert "1.2.3.4" in ind["source_ips"]

    def test_extracts_destination_ip(self):
        class _Ev:
            payload = {"dst_ip": "10.0.0.1"}
            event_type = "x"
        ind = extract_indicators(_Ev())
        assert "10.0.0.1" in ind["destination_ips"]

    def test_extracts_user(self):
        class _Ev:
            payload = {"user": "alice"}
            event_type = "x"
        ind = extract_indicators(_Ev())
        assert "alice" in ind["users"]

    def test_extracts_host(self):
        class _Ev:
            payload = {"host": "WS-01"}
            event_type = "x"
        ind = extract_indicators(_Ev())
        assert "WS-01" in ind["hosts"]

    def test_extracts_ioc(self):
        class _Ev:
            payload = {"signature": "trojan.win32.agent"}
            event_type = "x"
        ind = extract_indicators(_Ev())
        assert "trojan.win32.agent" in ind["iocs"]

    def test_extracts_multiple_from_rich_payload(self):
        class _Ev:
            payload = {
                "src_ip": "1.2.3.4",
                "dst_ip": "10.0.0.1",
                "user": "admin",
                "host": "DC-01",
                "signature": "hash-abc",
            }
            event_type = "x"
        ind = extract_indicators(_Ev())
        assert "1.2.3.4" in ind["source_ips"]
        assert "10.0.0.1" in ind["destination_ips"]
        assert "admin" in ind["users"]
        assert "DC-01" in ind["hosts"]
        assert "hash-abc" in ind["iocs"]

    def test_empty_payload_returns_empty_sets(self):
        class _Ev:
            payload = {}
            event_type = "x"
        ind = extract_indicators(_Ev())
        for v in ind.values():
            assert v == set()

    def test_detects_ip_loose_format(self):
        class _Ev:
            payload = {"remote": "185.220.101.5"}
            event_type = "x"
        ind = extract_indicators(_Ev())
        assert "185.220.101.5" in ind["source_ips"]


class TestComputeScore:
    def _mk(self, src=None, dst=None, user=None, host=None, ioc=None):
        return {
            "source_ips": {src} if src else set(),
            "destination_ips": {dst} if dst else set(),
            "users": {user} if user else set(),
            "hosts": {host} if host else set(),
            "iocs": {ioc} if ioc else set(),
        }

    def test_no_shared_indicators_zero(self):
        a = self._mk(src="1.1.1.1")
        b = self._mk(src="2.2.2.2")
        score, reasons = compute_score(a, b, None, None, "x", "y")
        assert score == 0.0
        assert reasons == []

    def test_same_source_ip(self):
        a = self._mk(src="1.2.3.4")
        b = self._mk(src="1.2.3.4")
        score, reasons = compute_score(a, b, None, None, "x", "x")
        assert score >= SCORE_WEIGHTS["same_source_ip"]
        assert any("source IP" in r for r in reasons)

    def test_same_destination_ip(self):
        a = self._mk(dst="10.0.0.1")
        b = self._mk(dst="10.0.0.1")
        score, _ = compute_score(a, b, None, None, "x", "x")
        assert score >= SCORE_WEIGHTS["same_destination_ip"]

    def test_same_user(self):
        a = self._mk(user="alice")
        b = self._mk(user="alice")
        score, _ = compute_score(a, b, None, None, "x", "x")
        assert score >= SCORE_WEIGHTS["same_user"]

    def test_same_host(self):
        a = self._mk(host="WS-01")
        b = self._mk(host="WS-01")
        score, _ = compute_score(a, b, None, None, "x", "x")
        assert score >= SCORE_WEIGHTS["same_host"]

    def test_same_ioc(self):
        a = self._mk(ioc="hash-abc")
        b = self._mk(ioc="hash-abc")
        score, _ = compute_score(a, b, None, None, "x", "x")
        assert score >= SCORE_WEIGHTS["same_ioc"]

    def test_multiple_indicators_add_up(self):
        a = self._mk(src="1.2.3.4", user="admin", host="WS-01")
        b = self._mk(src="1.2.3.4", user="admin", host="WS-01")
        # Both alerts use event_type "x" so related_event_type bonus also fires
        score, reasons = compute_score(a, b, None, None, "x", "x")
        expected = (
            SCORE_WEIGHTS["same_source_ip"]
            + SCORE_WEIGHTS["same_user"]
            + SCORE_WEIGHTS["same_host"]
            + SCORE_WEIGHTS["related_event_type"]
        )
        assert score == pytest.approx(expected, rel=1e-3)
        assert len(reasons) == 4

    def test_time_proximity_bonus(self):
        now = datetime.now(timezone.utc)
        a = self._mk(src="1.2.3.4")
        b = self._mk(src="1.2.3.4")
        score_close, _ = compute_score(a, b, now, now + timedelta(minutes=1), "x", "x")
        score_far, _ = compute_score(a, b, now, now + timedelta(hours=2), "x", "x")
        assert score_close > score_far

    def test_time_proximity_beyond_window_zero(self):
        now = datetime.now(timezone.utc)
        ts = _time_proximity_score(now, now + timedelta(hours=1), 15)
        assert ts == 0.0

    def test_time_proximity_same_time_full(self):
        now = datetime.now(timezone.utc)
        ts = _time_proximity_score(now, now, 15)
        assert ts == 1.0

    def test_event_types_related(self):
        assert _event_types_related("failed_login", "privilege_escalation")
        assert _event_types_related("failed_login", "failed_login")
        assert not _event_types_related("page_view", "failed_login")

    def test_max_severity(self):
        assert max_severity(["low", "medium", "high"]) == "high"
        assert max_severity(["info", "critical"]) == "critical"
        assert max_severity(["medium"]) == "medium"


# ===========================================================================
# CorrelationEngine tests
# ===========================================================================

class TestCorrelationSameSourceIP:
    def test_same_source_ip_close_timestamps_one_incident(self, db_session):
        now = datetime.now(timezone.utc)
        a1 = _make_alert(db_session, rule_name="R1", payload={"src_ip": "185.220.101.5"}, timestamp=now)
        a2 = _make_alert(db_session, rule_name="R2", payload={"src_ip": "185.220.101.5"}, timestamp=now + timedelta(minutes=3))
        a3 = _make_alert(db_session, rule_name="R3", payload={"src_ip": "185.220.101.5"}, timestamp=now + timedelta(minutes=7))
        db_session.commit()

        engine = CorrelationEngine(db_session)
        incidents = engine.correlate()

        assert len(incidents) == 1
        assert set(incidents[0].alert_ids) == {a1.id, a2.id, a3.id}
        assert incidents[0].alert_count == 3
        assert "185.220.101.5" in incidents[0].source_ips


class TestCorrelationSameUserHost:
    def test_same_user_and_host_one_incident(self, db_session):
        now = datetime.now(timezone.utc)
        a1 = _make_alert(db_session, rule_name="R1", payload={"user": "admin", "host": "DC-01"}, timestamp=now)
        a2 = _make_alert(db_session, rule_name="R2", payload={"user": "admin", "host": "DC-01"}, timestamp=now + timedelta(minutes=5))
        db_session.commit()

        engine = CorrelationEngine(db_session)
        incidents = engine.correlate()

        assert len(incidents) == 1
        assert set(incidents[0].alert_ids) == {a1.id, a2.id}
        assert "admin" in incidents[0].users
        assert "DC-01" in incidents[0].hosts


class TestCorrelationUnrelated:
    def test_unrelated_indicators_and_distant_timestamps_separate_incidents(self, db_session):
        now = datetime.now(timezone.utc)
        a1 = _make_alert(db_session, rule_name="R1", payload={"src_ip": "1.1.1.1", "user": "alice"}, timestamp=now)
        a2 = _make_alert(db_session, rule_name="R2", payload={"src_ip": "9.9.9.9", "user": "bob"}, timestamp=now + timedelta(hours=6))
        db_session.commit()

        engine = CorrelationEngine(db_session)
        incidents = engine.correlate()

        assert len(incidents) == 2
        all_ids = set()
        for i in incidents:
            all_ids.update(i.alert_ids)
        assert all_ids == {a1.id, a2.id}


class TestMultiStageAttack:
    def test_multi_stage_attack_one_incident(self, db_session):
        now = datetime.now(timezone.utc)
        a1 = _make_alert(
            db_session, rule_name="Brute Force", event_type="failed_login",
            payload={"src_ip": "185.220.101.5", "user": "admin", "host": "DC-01"},
            timestamp=now,
        )
        a2 = _make_alert(
            db_session, rule_name="Privilege Escalation", event_type="privilege_escalation",
            payload={"src_ip": "185.220.101.5", "user": "admin", "host": "DC-01"},
            timestamp=now + timedelta(minutes=2),
        )
        a3 = _make_alert(
            db_session, rule_name="Malware", event_type="malware_detected",
            payload={"src_ip": "185.220.101.5", "host": "DC-01", "signature": "trojan.win32"},
            timestamp=now + timedelta(minutes=5),
        )
        a4 = _make_alert(
            db_session, rule_name="Exfiltration", event_type="data_transfer",
            payload={"src_ip": "185.220.101.5", "dst_ip": "198.51.100.1", "bytes_transferred": 500000},
            timestamp=now + timedelta(minutes=8),
        )
        db_session.commit()

        engine = CorrelationEngine(db_session)
        incidents = engine.correlate()

        assert len(incidents) == 1
        assert set(incidents[0].alert_ids) == {a1.id, a2.id, a3.id, a4.id}
        assert incidents[0].alert_count == 4
        assert "185.220.101.5" in incidents[0].source_ips
        assert "DC-01" in incidents[0].hosts
        assert incidents[0].severity in ("high", "critical")
        assert incidents[0].title == "Multi-Stage Attack"


class TestCorrelationIdempotency:
    def test_second_run_creates_no_duplicates(self, db_session):
        now = datetime.now(timezone.utc)
        _make_alert(db_session, rule_name="R1", payload={"src_ip": "1.2.3.4"}, timestamp=now)
        _make_alert(db_session, rule_name="R2", payload={"src_ip": "1.2.3.4"}, timestamp=now + timedelta(minutes=2))
        db_session.commit()

        engine = CorrelationEngine(db_session)
        incidents_run1 = engine.correlate()
        assert len(incidents_run1) == 1
        first_id = incidents_run1[0].id

        # Re-run: no new alerts to process
        incidents_run2 = engine.correlate()
        assert len(incidents_run2) == 0

        # DB still has exactly one incident
        assert db_session.query(Incident).count() == 1
        assert db_session.query(Incident).first().id == first_id


class TestCorrelationScoreAndEvidence:
    def test_correlation_score_calculated(self, db_session):
        now = datetime.now(timezone.utc)
        _make_alert(db_session, rule_name="R1", payload={"src_ip": "1.2.3.4"}, timestamp=now)
        _make_alert(db_session, rule_name="R2", payload={"src_ip": "1.2.3.4"}, timestamp=now + timedelta(minutes=1))
        db_session.commit()

        engine = CorrelationEngine(db_session)
        incidents = engine.correlate()

        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.correlation_score is not None
        assert inc.correlation_score > 0
        # At minimum: same source IP (0.25) + time bonus
        assert inc.correlation_score >= SCORE_WEIGHTS["same_source_ip"]

    def test_correlation_reasons_preserved(self, db_session):
        now = datetime.now(timezone.utc)
        _make_alert(db_session, rule_name="R1", payload={"src_ip": "1.2.3.4", "user": "admin"}, timestamp=now)
        _make_alert(db_session, rule_name="R2", payload={"src_ip": "1.2.3.4", "user": "admin"}, timestamp=now + timedelta(minutes=2))
        db_session.commit()

        engine = CorrelationEngine(db_session)
        incidents = engine.correlate()

        inc = incidents[0]
        assert inc.correlation_reasons is not None
        assert len(inc.correlation_reasons) >= 2
        joined = " ".join(inc.correlation_reasons)
        assert "1.2.3.4" in joined
        assert "admin" in joined


class TestEdgeCases:
    def test_no_alerts_returns_empty(self, db_session):
        engine = CorrelationEngine(db_session)
        assert engine.correlate() == []

    def test_single_alert_creates_incident(self, db_session):
        _make_alert(db_session, rule_name="R1", payload={"src_ip": "1.1.1.1"})
        db_session.commit()

        engine = CorrelationEngine(db_session)
        incidents = engine.correlate()
        assert len(incidents) == 1
        assert incidents[0].alert_count == 1

    def test_alert_status_changed_to_correlated(self, db_session):
        now = datetime.now(timezone.utc)
        a1 = _make_alert(db_session, rule_name="R1", payload={"src_ip": "1.2.3.4"}, timestamp=now)
        a2 = _make_alert(db_session, rule_name="R2", payload={"src_ip": "1.2.3.4"}, timestamp=now + timedelta(minutes=1))
        db_session.commit()

        engine = CorrelationEngine(db_session)
        engine.correlate()

        db_session.refresh(a1)
        db_session.refresh(a2)
        assert a1.status == "correlated"
        assert a2.status == "correlated"
        assert a1.incident_id is not None
        assert a1.incident_id == a2.incident_id


# ===========================================================================
# API endpoint tests
# ===========================================================================

class TestIncidentsAPI:
    def _create_rule(self, client, name, pattern):
        return client.post(
            "/api/v1/rules/",
            json={
                "name": name,
                "rule_type": "pattern_match",
                "severity": "high",
                "conditions": {"type": "pattern_match", "field": "event_type", "pattern": pattern},
            },
        )

    def _post_event(self, client, event_type, payload):
        return client.post(
            "/api/v1/events/",
            json={"source": "test", "event_type": event_type, "severity": "medium", "payload": payload},
        )

    def test_correlate_endpoint_creates_incident(self, client):
        self._create_rule(client, "R1", "type_a")
        self._create_rule(client, "R2", "type_b")
        self._post_event(client, "type_a", {"src_ip": "1.2.3.4"})
        self._post_event(client, "type_b", {"src_ip": "1.2.3.4"})

        response = client.post("/api/v1/incidents/correlate")
        assert response.status_code == 200
        data = response.json()
        assert data["incidents_touched"] >= 1
        assert len(data["incident_ids"]) >= 1

    def test_list_incidents(self, client):
        self._create_rule(client, "ListR", "list_ev")
        self._post_event(client, "list_ev", {"src_ip": "5.5.5.5"})
        client.post("/api/v1/incidents/correlate")

        response = client.get("/api/v1/incidents/")
        assert response.status_code == 200
        assert len(response.json()) >= 1

    def test_get_incident_by_id(self, client):
        self._create_rule(client, "GetR", "get_ev")
        self._post_event(client, "get_ev", {"src_ip": "7.7.7.7"})
        corr = client.post("/api/v1/incidents/correlate").json()
        inc_id = corr["incident_ids"][0]

        response = client.get(f"/api/v1/incidents/{inc_id}")
        assert response.status_code == 200
        assert response.json()["id"] == inc_id

    def test_get_incident_alerts(self, client):
        self._create_rule(client, "AlertsR", "alerts_ev")
        self._post_event(client, "alerts_ev", {"src_ip": "8.8.8.8"})
        corr = client.post("/api/v1/incidents/correlate").json()
        inc_id = corr["incident_ids"][0]

        response = client.get(f"/api/v1/incidents/{inc_id}/alerts")
        assert response.status_code == 200
        assert len(response.json()) >= 1

    def test_get_nonexistent_incident_404(self, client):
        response = client.get("/api/v1/incidents/nonexistent-id")
        assert response.status_code == 404

    def test_update_incident_status(self, client):
        self._create_rule(client, "StatusR", "status_ev")
        self._post_event(client, "status_ev", {"src_ip": "9.9.9.9"})
        corr = client.post("/api/v1/incidents/correlate").json()
        inc_id = corr["incident_ids"][0]

        response = client.patch(f"/api/v1/incidents/{inc_id}/status?status=investigating")
        assert response.status_code == 200
        assert response.json()["status"] == "investigating"

    def test_correlate_empty_body(self, client):
        response = client.post("/api/v1/incidents/correlate")
        assert response.status_code == 200

    def test_realistic_attack_scenario(self, client):
        """Full end-to-end: 4 related alerts become ONE incident."""
        for name, pattern in [
            ("Brute Force Rule", "failed_login"),
            ("Priv Esc Rule", "privilege_escalation"),
            ("Malware Rule", "malware_detected"),
            ("Exfil Rule", "data_transfer"),
        ]:
            self._create_rule(client, name, pattern)

        attacker_ip = "185.220.101.42"
        target_host = "ws-042"
        target_user = "jdoe"

        self._post_event(client, "failed_login", {"src_ip": attacker_ip, "user": target_user, "host": target_host, "failed_attempts": 15})
        self._post_event(client, "privilege_escalation", {"src_ip": attacker_ip, "user": target_user, "host": target_host})
        self._post_event(client, "malware_detected", {"src_ip": attacker_ip, "host": target_host, "signature": "ransomware.darkside"})
        self._post_event(client, "data_transfer", {"src_ip": attacker_ip, "dst_ip": "198.51.100.50", "bytes_transferred": 5000000000})

        corr = client.post("/api/v1/incidents/correlate").json()
        assert corr["incidents_touched"] >= 1

        incidents = client.get("/api/v1/incidents/").json()
        matching = [i for i in incidents if attacker_ip in (i.get("source_ips") or [])]
        assert len(matching) >= 1

        incident = matching[0]
        assert incident["alert_count"] >= 3
        assert attacker_ip in incident["source_ips"]
        assert target_host in incident["hosts"]
        assert incident["correlation_score"] is not None
        assert incident["correlation_score"] > 0
        assert len(incident["correlation_reasons"]) >= 1
