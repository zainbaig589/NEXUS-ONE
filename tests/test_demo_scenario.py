"""Tests for the demo attack-scenario orchestrator and API endpoint."""

import pytest
from unittest.mock import patch

from app.demo.scenario import build_attack_scenario_events
from app.demo.service import DemoOrchestrator
from app.ai.errors import AIProviderError


# ---------------------------------------------------------------------------
# Scenario builder tests
# ---------------------------------------------------------------------------


class TestDemoScenario:
    def test_scenario_has_six_events(self):
        events = build_attack_scenario_events("test-run-123")
        assert len(events) == 6

    def test_scenario_event_types(self):
        events = build_attack_scenario_events("test-run-123")
        types = [e["event_type"] for e in events]
        assert types == [
            "failed_login",
            "failed_login",
            "failed_login",
            "successful_login",
            "privilege_escalation",
            "data_transfer",
        ]

    def test_scenario_timestamps_are_ordered(self):
        events = build_attack_scenario_events("test-run-123")
        timestamps = [e["timestamp"] for e in events]
        assert timestamps == sorted(timestamps)

    def test_scenario_contains_successful_login(self):
        events = build_attack_scenario_events("test-run-123")
        assert any(e["event_type"] == "successful_login" for e in events)

    def test_scenario_events_have_demo_run_id(self):
        events = build_attack_scenario_events("test-run-123")
        for event in events:
            assert event["payload"]["_demo_run_id"] == "test-run-123"

    def test_scenario_severities(self):
        events = build_attack_scenario_events("test-run-123")
        severities = [e["severity"] for e in events]
        assert severities == ["high", "high", "high", "medium", "critical", "critical"]


# ---------------------------------------------------------------------------
# Orchestrator tests
# ---------------------------------------------------------------------------


class TestDemoOrchestrator:
    def test_full_pipeline_succeeds(self, db_session):
        result = DemoOrchestrator().run(db_session)
        assert result.events_created == 6
        assert result.alerts_created >= 1
        assert len(result.incident_ids) >= 1
        assert result.primary_incident_id is not None
        assert result.investigation_status == "available"
        assert result.recommendation_count >= 1
        assert result.report_generated is True

    def test_returns_demo_run_id(self, db_session):
        result = DemoOrchestrator().run(db_session)
        assert result.demo_run_id
        assert len(result.demo_run_id) == 36  # UUID format

    def test_primary_incident_identified(self, db_session):
        result = DemoOrchestrator().run(db_session)
        assert result.primary_incident_id is not None
        assert result.primary_incident_id in result.incident_ids

    def test_risk_data_populated(self, db_session):
        result = DemoOrchestrator().run(db_session)
        assert result.risk_score is not None
        assert result.risk_level is not None
        assert result.risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_attack_stages_classified(self, db_session):
        result = DemoOrchestrator().run(db_session)
        assert len(result.attack_stages) >= 1
        stage_text = " ".join(result.attack_stages)
        assert "Credential Access" in stage_text or "Initial Access" in stage_text

    def test_rule_detections_present(self, db_session):
        result = DemoOrchestrator().run(db_session)
        assert result.rule_detections >= 1

    def test_all_stages_present(self, db_session):
        result = DemoOrchestrator().run(db_session)
        stage_names = [s.stage for s in result.stages]
        assert "INGEST" in stage_names
        assert "DETECT" in stage_names
        assert "CORRELATE" in stage_names
        assert "INVESTIGATE" in stage_names
        assert "RECOMMEND" in stage_names
        assert "REPORT" in stage_names

    def test_stage_results_have_timing(self, db_session):
        result = DemoOrchestrator().run(db_session)
        for stage in result.stages:
            assert stage.duration_ms >= 0

    def test_repeatable_rerun(self, db_session):
        result1 = DemoOrchestrator().run(db_session)
        result2 = DemoOrchestrator().run(db_session)
        assert result1.demo_run_id != result2.demo_run_id
        assert result1.events_created == 6
        assert result2.events_created == 6

    def test_investigation_failure_does_not_block(self, db_session):
        with patch(
            "app.demo.service.InvestigationService.investigate",
            side_effect=AIProviderError("mock failure"),
        ):
            result = DemoOrchestrator().run(db_session)
        assert result.investigation_status == "failed"
        investigate_stage = next(s for s in result.stages if s.stage == "INVESTIGATE")
        assert investigate_stage.status == "error"
        assert result.recommendation_count >= 1
        assert result.report_generated is True

    def test_recommendations_generated(self, db_session):
        result = DemoOrchestrator().run(db_session)
        assert result.recommendation_count >= 1

    def test_report_generated(self, db_session):
        result = DemoOrchestrator().run(db_session)
        assert result.report_generated is True

    def test_total_duration_tracked(self, db_session):
        result = DemoOrchestrator().run(db_session)
        assert result.total_duration_ms >= 0


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------


class TestDemoAPIEndpoint:
    def test_post_attack_scenario_returns_200(self, client):
        resp = client.post("/api/v1/demo/attack-scenario")
        assert resp.status_code == 200
        data = resp.json()
        assert "demo_run_id" in data
        assert "stages" in data

    def test_response_contains_all_stages(self, client):
        resp = client.post("/api/v1/demo/attack-scenario")
        data = resp.json()
        stage_names = [s["stage"] for s in data["stages"]]
        assert "INGEST" in stage_names
        assert "DETECT" in stage_names
        assert "CORRELATE" in stage_names

    def test_stage_results_have_timing(self, client):
        resp = client.post("/api/v1/demo/attack-scenario")
        data = resp.json()
        for stage in data["stages"]:
            assert stage["duration_ms"] >= 0

    def test_incident_ids_are_valid(self, client):
        resp = client.post("/api/v1/demo/attack-scenario")
        data = resp.json()
        for incident_id in data["incident_ids"]:
            get_resp = client.get(f"/api/v1/incidents/{incident_id}")
            assert get_resp.status_code == 200

    def test_repeatable_api(self, client):
        resp1 = client.post("/api/v1/demo/attack-scenario")
        resp2 = client.post("/api/v1/demo/attack-scenario")
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        data1 = resp1.json()
        data2 = resp2.json()
        assert data1["demo_run_id"] != data2["demo_run_id"]

    def test_primary_incident_has_risk(self, client):
        resp = client.post("/api/v1/demo/attack-scenario")
        data = resp.json()
        assert data["primary_incident_id"] is not None
        assert data["risk_score"] is not None
        assert data["risk_level"] is not None
