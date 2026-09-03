"""Tests for the enhanced AI demo provider output.

Covers:
- Enhanced demo report has non-empty executive summary
- Enhanced demo report findings reference valid evidence IDs
- Enhanced demo report next steps are non-empty
- Investigation with empty evidence handled gracefully
- Re-run investigation updates persisted record
- Demo report contains threat assessment
- Demo report contains attack narrative
- Demo report contains uncertainties
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from app.ai.context_builder import build_investigation_context
from app.ai.demo_provider import DemoInvestigatorProvider
from app.ai.validation import parse_and_validate
from app.correlation import CorrelationEngine
from app.models.alert import Alert
from app.models.event import Event
from app.models.rule import Rule
from app.services import CorrelationService, RiskService, TimelineService


def _make_alert(db_session, *, rule_name, severity="high", event_type="test_event",
                payload=None, timestamp=None):
    rule = db_session.query(Rule).filter(Rule.name == rule_name).first()
    if not rule:
        rule = Rule(
            name=rule_name, rule_type="pattern_match", severity=severity,
            conditions={"type": "pattern_match", "field": "event_type", "pattern": event_type},
            enabled=True,
        )
        db_session.add(rule)
        db_session.flush()

    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    event = Event(
        source="test", event_type=event_type, severity=severity,
        payload=payload or {}, timestamp=timestamp,
    )
    db_session.add(event)
    db_session.flush()

    alert = Alert(
        event_id=event.id, rule_id=rule.id, rule_name=rule_name,
        severity=severity, status="new",
    )
    db_session.add(alert)
    db_session.flush()
    return alert


def _multi_stage_attack(db_session):
    now = datetime.now(timezone.utc)
    _make_alert(
        db_session, rule_name="Brute Force Login Detection", severity="high",
        event_type="failed_login",
        payload={"src_ip": "185.220.101.5", "user": "admin", "host": "ws-042"},
        timestamp=now,
    )
    _make_alert(
        db_session, rule_name="Brute Force Login Detection", severity="high",
        event_type="failed_login",
        payload={"src_ip": "185.220.101.5", "user": "admin", "host": "ws-042"},
        timestamp=now + timedelta(minutes=2),
    )
    _make_alert(
        db_session, rule_name="Brute Force Login Detection", severity="high",
        event_type="failed_login",
        payload={"src_ip": "185.220.101.5", "user": "admin", "host": "ws-042"},
        timestamp=now + timedelta(minutes=4),
    )
    _make_alert(
        db_session, rule_name="Privilege Escalation Attempt", severity="critical",
        event_type="privilege_escalation",
        payload={"src_ip": "185.220.101.5", "user": "admin", "host": "ws-042", "new_role": "root"},
        timestamp=now + timedelta(minutes=7),
    )
    _make_alert(
        db_session, rule_name="Large Data Transfer", severity="critical",
        event_type="data_transfer",
        payload={
            "src_ip": "185.220.101.5", "dst_ip": "198.51.100.7",
            "user": "admin", "host": "ws-042", "bytes_transferred": 996147200,
        },
        timestamp=now + timedelta(minutes=12),
    )
    db_session.commit()

    engine = CorrelationEngine(db_session)
    incidents = engine.correlate()
    assert len(incidents) == 1
    return incidents[0]


def _run_demo_investigation(db_session, incident):
    alerts = CorrelationService.get_incident_alerts(db_session, incident.id)
    events_by_alert = {a.id: a.event for a in alerts}
    risk = RiskService.get_risk(db_session, incident.id)
    timeline = TimelineService.get_timeline(db_session, incident.id)

    ctx = build_investigation_context(incident, alerts, timeline, risk, events_by_alert)
    provider = DemoInvestigatorProvider()
    raw = provider.investigate(ctx.payload)
    report = parse_and_validate(raw, ctx)
    return report, ctx


class TestEnhancedDemoProvider:
    def test_non_empty_executive_summary(self, db_session):
        incident = _multi_stage_attack(db_session)
        report, ctx = _run_demo_investigation(db_session, incident)
        assert report.incident_summary
        assert len(report.incident_summary) > 50

    def test_findings_reference_valid_evidence(self, db_session):
        incident = _multi_stage_attack(db_session)
        report, ctx = _run_demo_investigation(db_session, incident)
        valid_ids = ctx.evidence_ids
        for finding in report.investigation_findings:
            for eid in finding.evidence_ids:
                assert eid in valid_ids, f"Finding references invalid evidence: {eid}"

    def test_next_steps_non_empty(self, db_session):
        incident = _multi_stage_attack(db_session)
        report, ctx = _run_demo_investigation(db_session, incident)
        assert len(report.recommended_next_steps) > 0

    def test_threat_assessment_non_empty(self, db_session):
        incident = _multi_stage_attack(db_session)
        report, ctx = _run_demo_investigation(db_session, incident)
        assert report.threat_assessment
        assert len(report.threat_assessment) > 30

    def test_attack_narrative_non_empty(self, db_session):
        incident = _multi_stage_attack(db_session)
        report, ctx = _run_demo_investigation(db_session, incident)
        assert report.attack_narrative
        assert len(report.attack_narrative) > 50

    def test_uncertainties_non_empty(self, db_session):
        incident = _multi_stage_attack(db_session)
        report, ctx = _run_demo_investigation(db_session, incident)
        assert len(report.uncertainties) > 0

    def test_evidence_items_non_empty(self, db_session):
        incident = _multi_stage_attack(db_session)
        report, ctx = _run_demo_investigation(db_session, incident)
        assert len(report.evidence) > 0

    def test_attack_stages_detected(self, db_session):
        incident = _multi_stage_attack(db_session)
        report, ctx = _run_demo_investigation(db_session, incident)
        assert len(report.potential_attack_stages) > 0

    def test_affected_entities_populated(self, db_session):
        incident = _multi_stage_attack(db_session)
        report, ctx = _run_demo_investigation(db_session, incident)
        assert len(report.affected_entities) > 0

    def test_confidence_in_range(self, db_session):
        incident = _multi_stage_attack(db_session)
        report, ctx = _run_demo_investigation(db_session, incident)
        assert 0.0 <= report.confidence <= 1.0

    def test_empty_evidence_handled_gracefully(self):
        empty_payload = {
            "incident": {
                "id": "test-empty",
                "title": "Empty Incident",
                "severity": "low",
                "status": "open",
                "description": None,
                "first_seen": None,
                "last_seen": None,
                "alert_count": 0,
                "correlation_score": 0,
                "correlation_reasons": [],
            },
            "deterministic_risk_assessment": None,
            "alerts": [],
            "timeline": {"first_seen": None, "last_seen": None, "duration_seconds": 0},
            "potential_attack_stages": [],
            "observed_entities": {"hosts": [], "users": [], "source_ips": [], "destination_ips": []},
        }
        provider = DemoInvestigatorProvider()
        raw = provider.investigate(empty_payload)
        data = json.loads(raw)
        assert data["incident_summary"]
        assert 0.0 <= data["confidence"] <= 1.0

    def test_rerun_produces_same_result(self, db_session):
        incident = _multi_stage_attack(db_session)
        report1, _ = _run_demo_investigation(db_session, incident)
        report2, _ = _run_demo_investigation(db_session, incident)
        assert report1.incident_summary == report2.incident_summary
        assert report1.confidence == report2.confidence

    def test_investigation_service_persists(self, db_session):
        from app.ai.service import InvestigationService
        incident = _multi_stage_attack(db_session)
        result = InvestigationService.investigate(db_session, incident.id)
        assert result is not None
        assert result["provider"] == "demo"
        assert "DEMO" in result["analysis_mode"].upper()

        fetched = InvestigationService.get_investigation(db_session, incident.id)
        assert fetched is not None
        assert fetched["provider"] == "demo"
