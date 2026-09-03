"""Tests for PDF report generation.

Covers:
- PDF generation returns valid PDF bytes
- PDF contains incident ID, severity, risk score
- PDF contains evidence table data
- PDF contains attack stages
- PDF contains findings
- PDF contains recommendations
- PDF contains investigation metadata
- PDF contains DEMO mode notice when applicable
- PDF endpoint returns correct content-type
- PDF endpoint returns 404 for missing incident
- PDF download filename includes incident ID
"""

import re
import zlib
from datetime import datetime, timedelta, timezone

import pytest

from app.ai.demo_provider import DemoInvestigatorProvider
from app.correlation import CorrelationEngine
from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Incident
from app.models.rule import Rule
from app.reports.pdf import render_report_pdf
from app.reports.service import ReportService
from app.services import RiskService


def _extract_pdf_text(pdf_bytes: bytes) -> str:
    """Extract text content from PDF by decompressing FlateDecode streams."""
    text_parts = []
    pattern = re.compile(rb'stream\r?\n(.+?)\r?\nendstream', re.DOTALL)
    for match in pattern.finditer(pdf_bytes):
        stream_data = match.group(1)
        try:
            decompressed = zlib.decompress(stream_data)
            text_ops = re.findall(rb'\(([^)]*)\)', decompressed)
            for op in text_ops:
                try:
                    text_parts.append(op.decode('latin-1'))
                except:
                    pass
        except:
            pass
    return ' '.join(text_parts)


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


def _generate_report(db_session, incident):
    report = ReportService.generate_report(db_session, incident.id)
    assert report is not None
    return report


class TestPdfGeneration:
    def test_pdf_returns_valid_bytes(self, db_session):
        incident = _multi_stage_attack(db_session)
        report = _generate_report(db_session, incident)
        pdf_bytes = render_report_pdf(report)
        assert pdf_bytes[:5] == b"%PDF-"

    def test_pdf_contains_incident_id(self, db_session):
        incident = _multi_stage_attack(db_session)
        report = _generate_report(db_session, incident)
        pdf_bytes = render_report_pdf(report)
        text = _extract_pdf_text(pdf_bytes)
        assert incident.id in text

    def test_pdf_contains_severity(self, db_session):
        incident = _multi_stage_attack(db_session)
        report = _generate_report(db_session, incident)
        pdf_bytes = render_report_pdf(report)
        text = _extract_pdf_text(pdf_bytes)
        assert incident.severity.upper() in text

    def test_pdf_contains_risk_score(self, db_session):
        incident = _multi_stage_attack(db_session)
        risk = RiskService.get_risk(db_session, incident.id)
        report = _generate_report(db_session, incident)
        pdf_bytes = render_report_pdf(report)
        text = _extract_pdf_text(pdf_bytes)
        if risk and risk.get("risk_score") is not None:
            assert str(int(risk["risk_score"])) in text

    def test_pdf_contains_findings(self, db_session):
        incident = _multi_stage_attack(db_session)
        report = _generate_report(db_session, incident)
        pdf_bytes = render_report_pdf(report)
        text = _extract_pdf_text(pdf_bytes)
        assert "FINDING" in text.upper() or "Finding" in text

    def test_pdf_contains_recommendations(self, db_session):
        incident = _multi_stage_attack(db_session)
        report = _generate_report(db_session, incident)
        pdf_bytes = render_report_pdf(report)
        text = _extract_pdf_text(pdf_bytes)
        assert "RECOMMEND" in text.upper() or "Recommend" in text

    def test_pdf_contains_investigation_metadata(self, db_session):
        incident = _multi_stage_attack(db_session)
        report = _generate_report(db_session, incident)
        pdf_bytes = render_report_pdf(report)
        text = _extract_pdf_text(pdf_bytes)
        assert "INVESTIGATION" in text.upper()

    def test_pdf_contains_demo_notice(self, db_session):
        incident = _multi_stage_attack(db_session)
        report = _generate_report(db_session, incident)
        if report.analysis.ai_investigation and "DEMO" in (
            report.analysis.investigation_metadata.analysis_mode or ""
        ).upper():
            pdf_bytes = render_report_pdf(report)
            text = _extract_pdf_text(pdf_bytes)
            assert "DEMO" in text

    def test_pdf_contains_evidence_integrity(self, db_session):
        incident = _multi_stage_attack(db_session)
        report = _generate_report(db_session, incident)
        pdf_bytes = render_report_pdf(report)
        text = _extract_pdf_text(pdf_bytes)
        assert "INTEGRITY" in text.upper() or "integrity" in text

    def test_pdf_contains_cover_page(self, db_session):
        incident = _multi_stage_attack(db_session)
        report = _generate_report(db_session, incident)
        pdf_bytes = render_report_pdf(report)
        text = _extract_pdf_text(pdf_bytes)
        assert "NEXUS ONE" in text
        assert "SECURITY INCIDENT" in text.upper()

    def test_pdf_contains_attack_stages(self, db_session):
        incident = _multi_stage_attack(db_session)
        report = _generate_report(db_session, incident)
        pdf_bytes = render_report_pdf(report)
        text = _extract_pdf_text(pdf_bytes)
        assert "ATTACK" in text.upper()

    def test_pdf_contains_timeline(self, db_session):
        incident = _multi_stage_attack(db_session)
        report = _generate_report(db_session, incident)
        pdf_bytes = render_report_pdf(report)
        text = _extract_pdf_text(pdf_bytes)
        assert "TIMELINE" in text.upper()


class TestPdfEndpoint:
    def test_pdf_endpoint_returns_correct_content_type(self, client, db_session):
        incident = _multi_stage_attack(db_session)
        response = client.post(f"/api/v1/incidents/{incident.id}/report?format=pdf")
        assert response.status_code == 200
        assert "application/pdf" in response.headers["content-type"]

    def test_pdf_endpoint_returns_pdf_bytes(self, client, db_session):
        incident = _multi_stage_attack(db_session)
        response = client.post(f"/api/v1/incidents/{incident.id}/report?format=pdf")
        assert response.status_code == 200
        assert response.content[:5] == b"%PDF-"

    def test_pdf_endpoint_returns_404_for_missing_incident(self, client, db_session):
        response = client.post("/api/v1/incidents/nonexistent-id/report?format=pdf")
        assert response.status_code == 404

    def test_pdf_get_endpoint(self, client, db_session):
        incident = _multi_stage_attack(db_session)
        client.post(f"/api/v1/incidents/{incident.id}/report")
        response = client.get(f"/api/v1/incidents/{incident.id}/report?format=pdf")
        assert response.status_code == 200
        assert "application/pdf" in response.headers["content-type"]
        assert response.content[:5] == b"%PDF-"

    def test_pdf_download_filename(self, client, db_session):
        incident = _multi_stage_attack(db_session)
        response = client.post(f"/api/v1/incidents/{incident.id}/report?format=pdf")
        assert response.status_code == 200
        disposition = response.headers.get("content-disposition", "")
        assert incident.id in disposition
        assert "pdf" in disposition.lower()
