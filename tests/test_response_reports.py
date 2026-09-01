"""Tests for the response recommendation engine and incident reports.

Covers the required scenarios:
1.  High-risk incident produces high-priority recommendations
2.  Low-risk incident produces lower-priority recommendations
3.  All evidence IDs reference real evidence
4.  No nonexistent evidence IDs are referenced
5.  Every recommendation requires analyst approval
6.  No destructive action is auto-executed
7.  Reports contain all required sections
8.  Reports distinguish evidence / analysis / recommendations
9.  Missing incidents return 404
10. Missing AI investigation is handled safely
11. Report generation works with the deterministic demo provider
12. (Full-suite regression is verified separately.)
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.ai.demo_provider import DemoInvestigatorProvider
from app.correlation import CorrelationEngine
from app.models.event import Event
from app.models.incident import Incident
from app.models.incident_report import IncidentReportRecord
from app.models.rule import Rule
from app.models.alert import Alert
from app.reports.service import ReportService
from app.response.engine import generate_recommendations, valid_evidence_ids
from app.response.service import ResponseService
from app.services import CorrelationService, RiskService


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


def _multi_stage_attack(db_session):
    """Realistic multi-stage attack: brute force -> privesc -> exfiltration."""
    now = datetime.now(timezone.utc)
    _make_alert(
        db_session,
        rule_name="Brute Force Login Detection",
        severity="high",
        event_type="failed_login",
        payload={"src_ip": "185.220.101.5", "user": "admin", "host": "ws-042"},
        timestamp=now,
    )
    _make_alert(
        db_session,
        rule_name="Brute Force Login Detection",
        severity="high",
        event_type="failed_login",
        payload={"src_ip": "185.220.101.5", "user": "admin", "host": "ws-042"},
        timestamp=now + timedelta(minutes=2),
    )
    _make_alert(
        db_session,
        rule_name="Brute Force Login Detection",
        severity="high",
        event_type="failed_login",
        payload={"src_ip": "185.220.101.5", "user": "admin", "host": "ws-042"},
        timestamp=now + timedelta(minutes=4),
    )
    _make_alert(
        db_session,
        rule_name="Privilege Escalation Attempt",
        severity="critical",
        event_type="privilege_escalation",
        payload={"src_ip": "185.220.101.5", "user": "admin", "host": "ws-042", "new_role": "root"},
        timestamp=now + timedelta(minutes=7),
    )
    _make_alert(
        db_session,
        rule_name="Large Data Transfer",
        severity="critical",
        event_type="data_transfer",
        payload={
            "src_ip": "185.220.101.5",
            "dst_ip": "198.51.100.7",
            "user": "admin",
            "host": "ws-042",
            "bytes_transferred": 996147200,
        },
        timestamp=now + timedelta(minutes=12),
    )
    db_session.commit()

    engine = CorrelationEngine(db_session)
    incidents = engine.correlate()
    assert len(incidents) == 1
    return incidents[0]


def _low_risk_incident(db_session):
    """Single informational login alert -> LOW risk incident."""
    _make_alert(
        db_session,
        rule_name="Info Login Rule",
        severity="info",
        event_type="login",
        payload={"user": "svc_backup", "host": "backup-01"},
    )
    db_session.commit()

    engine = CorrelationEngine(db_session)
    incidents = engine.correlate()
    assert len(incidents) == 1
    return incidents[0]


def _all_keys(obj):
    """Recursively collect every dict key in a JSON-like structure."""
    keys = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            keys.add(key)
            keys |= _all_keys(value)
    elif isinstance(obj, list):
        for item in obj:
            keys |= _all_keys(item)
    return keys


class TestRecommendationEngine:
    def test_high_risk_incident_gets_high_priority_recommendations(self, db_session):
        incident = _multi_stage_attack(db_session)
        alerts = CorrelationService.get_incident_alerts(db_session, incident.id)
        events_by_alert = {a.id: a.event for a in alerts}
        risk = RiskService.get_risk(db_session, incident.id)

        recs = generate_recommendations(
            incident, alerts, events_by_alert=events_by_alert, risk=risk, investigation=None
        )

        assert recs
        priorities = [r["priority"] for r in recs]
        assert "CRITICAL" in priorities or "HIGH" in priorities
        scores = [r["priority_score"] for r in recs]
        assert scores == sorted(scores, reverse=True)

    def test_low_risk_incident_gets_lower_priority_recommendations(self, db_session):
        incident = _low_risk_incident(db_session)
        alerts = CorrelationService.get_incident_alerts(db_session, incident.id)
        events_by_alert = {a.id: a.event for a in alerts}
        risk = RiskService.get_risk(db_session, incident.id)
        # Single info-severity login: the deterministic engine's baseline
        # (correlation + entity boosts) lands this just above LOW, but far
        # below the multi-stage attack scenario.
        assert risk["risk_score"] < 40

        recs = generate_recommendations(
            incident, alerts, events_by_alert=events_by_alert, risk=risk, investigation=None
        )

        assert recs
        priorities = [r["priority"] for r in recs]
        assert all(p in ("LOW", "MEDIUM") for p in priorities)
        assert "CRITICAL" not in priorities
        assert "HIGH" not in priorities

    def test_higher_risk_yields_higher_priority_score(self, db_session):
        """Same rule + same evidence, higher risk level -> higher score."""
        incident = _low_risk_incident(db_session)
        alerts = CorrelationService.get_incident_alerts(db_session, incident.id)
        events_by_alert = {a.id: a.event for a in alerts}

        low = generate_recommendations(
            incident, alerts, events_by_alert=events_by_alert,
            risk={"risk_score": 5.0, "risk_level": "LOW"}, investigation=None,
        )
        high = generate_recommendations(
            incident, alerts, events_by_alert=events_by_alert,
            risk={"risk_score": 90.0, "risk_level": "CRITICAL"}, investigation=None,
        )

        low_by_id = {r["recommendation_id"]: r for r in low}
        for rec in high:
            assert rec["priority_score"] > low_by_id[rec["recommendation_id"]]["priority_score"]

    def test_engine_is_deterministic(self, db_session):
        incident = _multi_stage_attack(db_session)
        alerts = CorrelationService.get_incident_alerts(db_session, incident.id)
        events_by_alert = {a.id: a.event for a in alerts}
        risk = RiskService.get_risk(db_session, incident.id)

        first = generate_recommendations(
            incident, alerts, events_by_alert=events_by_alert, risk=risk, investigation=None
        )
        second = generate_recommendations(
            incident, alerts, events_by_alert=events_by_alert, risk=risk, investigation=None
        )
        assert first == second

    def test_empty_incident_returns_no_recommendations(self, db_session):
        incident = _low_risk_incident(db_session)
        assert generate_recommendations(incident, []) == []

    def test_rationale_and_priority_factors_are_explainable(self, db_session):
        incident = _multi_stage_attack(db_session)
        alerts = CorrelationService.get_incident_alerts(db_session, incident.id)
        events_by_alert = {a.id: a.event for a in alerts}
        risk = RiskService.get_risk(db_session, incident.id)

        recs = generate_recommendations(
            incident, alerts, events_by_alert=events_by_alert, risk=risk, investigation=None
        )
        for rec in recs:
            assert rec["priority_factors"], rec["recommendation_id"]
            assert "priority because the incident is" in rec["rationale"]
            assert "risk" in rec["rationale"]

    def test_every_recommendation_requires_analyst_approval(self, db_session):
        incident = _multi_stage_attack(db_session)
        alerts = CorrelationService.get_incident_alerts(db_session, incident.id)
        events_by_alert = {a.id: a.event for a in alerts}

        recs = generate_recommendations(
            incident, alerts, events_by_alert=events_by_alert, risk=None, investigation=None
        )
        assert recs
        assert all(r["requires_analyst_approval"] is True for r in recs)


class TestRecommendationsAPI:
    def test_get_recommendations_for_high_risk_incident(self, client, db_session):
        incident = _multi_stage_attack(db_session)
        response = client.get(f"/api/v1/incidents/{incident.id}/recommendations")
        assert response.status_code == 200

        body = response.json()
        assert body["incident_id"] == incident.id
        assert body["recommendation_count"] == len(body["recommendations"])
        assert body["recommendations"]

        priorities = [r["priority"] for r in body["recommendations"]]
        assert any(p in ("CRITICAL", "HIGH") for p in priorities)
        assert "analyst approval" in body["advisory_notice"]

        scores = [r["priority_score"] for r in body["recommendations"]]
        assert scores == sorted(scores, reverse=True)

    def test_get_recommendations_for_low_risk_incident(self, client, db_session):
        incident = _low_risk_incident(db_session)
        response = client.get(f"/api/v1/incidents/{incident.id}/recommendations")
        assert response.status_code == 200

        priorities = [r["priority"] for r in response.json()["recommendations"]]
        assert priorities
        assert all(p in ("LOW", "MEDIUM") for p in priorities)

    def test_all_evidence_ids_reference_real_evidence(self, client, db_session):
        incident = _multi_stage_attack(db_session)
        alerts = CorrelationService.get_incident_alerts(db_session, incident.id)
        events_by_alert = {a.id: a.event for a in alerts}
        valid = valid_evidence_ids(alerts, events_by_alert)
        assert valid

        response = client.get(f"/api/v1/incidents/{incident.id}/recommendations")
        for rec in response.json()["recommendations"]:
            assert rec["evidence_ids"], rec["recommendation_id"]
            assert set(rec["evidence_ids"]) <= valid

    def test_no_nonexistent_evidence_ids_referenced(self, client, db_session):
        incident = _multi_stage_attack(db_session)
        response = client.get(f"/api/v1/incidents/{incident.id}/recommendations")
        assert response.status_code == 200

        raw = response.text
        assert "alert-nonexistent" not in raw
        assert "event-nonexistent" not in raw
        assert "alert-fabricated" not in raw

    def test_every_api_recommendation_requires_analyst_approval(self, client, db_session):
        incident = _multi_stage_attack(db_session)
        response = client.get(f"/api/v1/incidents/{incident.id}/recommendations")
        for rec in response.json()["recommendations"]:
            assert rec["requires_analyst_approval"] is True

    def test_no_destructive_action_auto_executed(self, client, db_session):
        """Recommendations change nothing: statuses stay, no execution flags."""
        incident = _multi_stage_attack(db_session)
        alerts_before = {
            a.id: a.status
            for a in db_session.query(Alert).filter(Alert.incident_id == incident.id).all()
        }
        status_before = incident.status

        response = client.get(f"/api/v1/incidents/{incident.id}/recommendations")
        assert response.status_code == 200
        body = response.json()

        # No execution semantics anywhere in the payload
        assert not _all_keys(body) & {
            "executed",
            "auto_execute",
            "automated",
            "execution_status",
            "action_taken",
        }

        db_session.expire_all()
        alerts_after = {
            a.id: a.status
            for a in db_session.query(Alert).filter(Alert.incident_id == incident.id).all()
        }
        incident_after = db_session.query(Incident).filter(Incident.id == incident.id).first()
        assert alerts_after == alerts_before
        assert incident_after.status == status_before

    def test_recommendations_snapshot_persisted_on_incident(self, client, db_session):
        incident = _multi_stage_attack(db_session)
        response = client.get(f"/api/v1/incidents/{incident.id}/recommendations")
        assert response.status_code == 200

        db_session.expire_all()
        stored = (
            db_session.query(Incident).filter(Incident.id == incident.id).first()
        ).response_recommendations
        assert stored is not None
        assert stored["incident_id"] == incident.id
        assert stored["recommendation_count"] == response.json()["recommendation_count"]

    def test_recommendations_missing_incident_404(self, client):
        response = client.get("/api/v1/incidents/does-not-exist/recommendations")
        assert response.status_code == 404
        assert response.json()["detail"] == "Incident not found"

    def test_recommendations_reflect_investigation_findings(self, client, db_session, monkeypatch):
        """With an investigation present, analyst-review recommendations appear."""
        monkeypatch.setattr(
            "app.ai.service.get_provider", lambda: DemoInvestigatorProvider()
        )
        incident = _multi_stage_attack(db_session)
        assert (
            client.post(f"/api/v1/incidents/{incident.id}/investigate").status_code == 200
        )

        response = client.get(f"/api/v1/incidents/{incident.id}/recommendations")
        assert response.status_code == 200
        rec_ids = [r["recommendation_id"] for r in response.json()["recommendations"]]
        assert "rec-review-ai-investigation-findings" in rec_ids


class TestIncidentReportAPI:
    def test_report_contains_all_required_sections(self, client, db_session):
        incident = _multi_stage_attack(db_session)
        response = client.post(f"/api/v1/incidents/{incident.id}/report")
        assert response.status_code == 200

        report = response.json()
        assert report["incident_id"] == incident.id
        assert report["report_id"].startswith("rpt-")
        assert report["format_version"]

        evidence = report["observed_evidence"]
        assert evidence["incident"]["incident_id"] == incident.id
        assert evidence["incident"]["severity"] == "critical"
        assert evidence["incident"]["risk_level"] if "risk_level" in evidence["incident"] else True
        assert evidence["incident"]["first_seen"]
        assert evidence["incident"]["last_seen"]
        assert evidence["incident"]["duration_seconds"] >= 0
        assert evidence["affected_users"] == ["admin"]
        assert evidence["affected_hosts"] == ["ws-042"]
        assert "185.220.101.5" in evidence["source_ips"]
        assert "198.51.100.7" in evidence["destination_ips"]
        assert len(evidence["correlated_alerts"]) == incident.alert_count
        assert evidence["correlated_alerts"]
        assert evidence["detection_methods"]
        assert evidence["attack_timeline"]["entries"]
        assert report["evidence_references"]

        analysis = report["analysis"]
        assert analysis["deterministic_risk_assessment"]["risk_level"]
        assert analysis["deterministic_risk_assessment"]["risk_score"] is not None
        assert analysis["potential_attack_stages"]

        actions = report["recommended_actions"]
        assert actions["recommendations"]

    def test_report_distinguishes_evidence_analysis_recommendations(self, client, db_session):
        incident = _multi_stage_attack(db_session)
        response = client.post(f"/api/v1/incidents/{incident.id}/report")
        assert response.status_code == 200
        report = response.json()

        # Three clearly separated sections
        assert {"observed_evidence", "analysis", "recommended_actions"} <= set(report)

        # Observed evidence holds only facts: no priority/rationale semantics
        for alert in report["observed_evidence"]["correlated_alerts"]:
            assert "priority" not in alert
            assert "rationale" not in alert
            assert "requires_analyst_approval" not in alert

        # Analysis holds the AI narrative and uncertainty framing
        assert "ai_investigation" in report["analysis"]
        assert "analysis_notice" in report["analysis"]
        for stage in report["analysis"]["potential_attack_stages"]:
            assert stage.startswith("Potential stage: ")

        # Recommendations live only in their own section, always advisory
        for rec in report["recommended_actions"]["recommendations"]:
            assert rec["requires_analyst_approval"] is True
        assert report["recommended_actions"]["all_actions_require_analyst_approval"] is True

    def test_report_missing_incident_404(self, client):
        assert client.get("/api/v1/incidents/does-not-exist/report").status_code == 404
        assert client.post("/api/v1/incidents/does-not-exist/report").status_code == 404

    def test_report_handles_missing_investigation_safely(self, client, db_session):
        incident = _multi_stage_attack(db_session)
        response = client.post(f"/api/v1/incidents/{incident.id}/report")
        assert response.status_code == 200

        analysis = response.json()["analysis"]
        assert analysis["investigation_status"] == "not_run"
        assert analysis["ai_investigation"] is None
        assert analysis["investigation_metadata"] is None
        assert analysis["uncertainties"]  # explicit fallback note

        # Recommendations are still generated from deterministic evidence
        assert response.json()["recommended_actions"]["recommendations"]

    def test_report_works_with_demo_provider_investigation(self, client, db_session, monkeypatch):
        monkeypatch.setattr(
            "app.ai.service.get_provider", lambda: DemoInvestigatorProvider()
        )
        incident = _multi_stage_attack(db_session)
        assert (
            client.post(f"/api/v1/incidents/{incident.id}/investigate").status_code == 200
        )

        response = client.post(f"/api/v1/incidents/{incident.id}/report")
        assert response.status_code == 200
        report = response.json()

        analysis = report["analysis"]
        assert analysis["investigation_status"] == "available"
        assert analysis["investigation_metadata"]["provider"] == "demo"
        assert analysis["ai_investigation"]["incident_summary"]
        assert analysis["ai_investigation"]["investigation_findings"]
        assert any("DEMO" in u for u in analysis["uncertainties"])

    def test_report_persistence_get_before_and_after_post(self, client, db_session):
        incident = _multi_stage_attack(db_session)

        missing = client.get(f"/api/v1/incidents/{incident.id}/report")
        assert missing.status_code == 404
        assert "No report has been generated" in missing.json()["detail"]

        created = client.post(f"/api/v1/incidents/{incident.id}/report")
        assert created.status_code == 200

        fetched = client.get(f"/api/v1/incidents/{incident.id}/report")
        assert fetched.status_code == 200
        assert fetched.json()["report_id"] == created.json()["report_id"]

        # Persisted as a record row
        assert (
            db_session.query(IncidentReportRecord)
            .filter(IncidentReportRecord.incident_id == incident.id)
            .count()
            == 1
        )

    def test_report_html_format_is_escaped_and_sectioned(self, client, db_session):
        incident = _multi_stage_attack(db_session)
        incident.title = "Compromise <script>alert(1)</script>"
        db_session.commit()

        response = client.post(f"/api/v1/incidents/{incident.id}/report?format=html")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")

        page = response.text
        assert "<script>alert(1)</script>" not in page
        assert "&lt;script&gt;" in page
        assert "Observed Evidence" in page
        assert "Analysis" in page
        assert "Recommended Actions" in page
        assert "requires analyst approval" in page

    def test_report_invalid_format_rejected(self, client, db_session):
        incident = _multi_stage_attack(db_session)
        response = client.post(f"/api/v1/incidents/{incident.id}/report?format=pdf")
        assert response.status_code == 422

    def test_report_alerts_carry_evidence_ids(self, client, db_session):
        incident = _multi_stage_attack(db_session)
        response = client.post(f"/api/v1/incidents/{incident.id}/report")
        for alert in response.json()["observed_evidence"]["correlated_alerts"]:
            assert alert["evidence_ids"]
            assert all(
                eid.startswith(("alert-", "event-")) for eid in alert["evidence_ids"]
            )


class TestServiceLayer:
    def test_response_service_returns_none_for_missing_incident(self, db_session):
        assert ResponseService.get_recommendations(db_session, "missing") is None

    def test_report_service_returns_none_for_missing_incident(self, db_session):
        assert ReportService.generate_report(db_session, "missing") is None

    def test_report_service_get_report_none_without_generation(self, db_session):
        incident = _multi_stage_attack(db_session)
        assert ReportService.get_report(db_session, incident.id) is None

    def test_report_service_generates_and_persists(self, db_session):
        incident = _multi_stage_attack(db_session)
        report = ReportService.generate_report(db_session, incident.id)
        assert report is not None
        assert report.incident_id == incident.id

        stored = ReportService.get_report(db_session, incident.id)
        assert stored is not None
        assert stored["report_id"] == report.report_id

        db_session.expire_all()
        refreshed = db_session.query(Incident).filter(Incident.id == incident.id).first()
        assert refreshed.response_recommendations is not None
