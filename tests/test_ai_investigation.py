"""Tests for the AI-powered incident investigation layer.

All LLM interactions use fake/demo providers — no real API calls are made.
"""

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Callable, Dict, Optional, Union

import httpx
import pytest

from app.ai.context_builder import InvestigationContext, build_investigation_context
from app.ai.demo_provider import DemoInvestigatorProvider
from app.ai.errors import (
    AIEvidenceValidationError,
    AIContextTooLargeError,
    AIProviderError,
    AIProviderNotConfiguredError,
    AIProviderTimeoutError,
    AIResponseValidationError,
)
from app.ai.prompts import SYSTEM_PROMPT, build_messages, build_user_prompt
from app.ai.providers import LLMProvider, OpenAICompatibleProvider, get_provider
from app.ai.validation import parse_and_validate
from app.config import settings
from app.correlation import CorrelationEngine
from app.services import CorrelationService, RiskService, TimelineService
from tests.test_risk_timeline import _make_alert


ALLOWED_CONTEXT_KEYS = {
    "incident",
    "deterministic_risk_assessment",
    "alerts",
    "timeline",
    "potential_attack_stages",
    "observed_entities",
    "context_notes",
}

ALLOWED_ALERT_KEYS = {
    "id",
    "event_id",
    "timestamp",
    "event_type",
    "rule_name",
    "severity",
    "detection_method",
    "detection_reason",
    "source_ip",
    "destination_ip",
    "user",
    "host",
    "ml_anomaly",
    "potential_attack_stage",
}


class FakeProvider(LLMProvider):
    """Configurable stand-in for a real LLM provider."""

    name = "fake"

    def __init__(
        self,
        response: Union[str, Callable[[Dict[str, Any]], str], None] = None,
        error: Optional[Exception] = None,
    ):
        self.response = response if response is not None else "{}"
        self.error = error
        self.contexts: list = []

    def investigate(self, context: Dict[str, Any]) -> str:
        self.contexts.append(context)
        if self.error:
            raise self.error
        if callable(self.response):
            return self.response(context)
        return self.response


def valid_report_for(context: Dict[str, Any]) -> str:
    """Build a schema-valid, fully-cited report from the supplied context."""
    evidence_ids: list = []
    for alert in context.get("alerts", []):
        for identifier in (alert.get("id"), alert.get("event_id")):
            if identifier:
                evidence_ids.append(identifier)

    report = {
        "incident_summary": f"Incident with {len(evidence_ids) // 2} correlated alerts.",
        "threat_assessment": "Activity is consistent with credential abuse; not confirmed.",
        "evidence": [
            {"description": "Correlated alerts on shared infrastructure", "evidence_ids": evidence_ids}
        ],
        "attack_narrative": "Observed alerts occurred in sequence on the same assets.",
        "potential_attack_stages": context.get("potential_attack_stages", []),
        "affected_entities": list(context.get("observed_entities", {}).get("hosts", [])),
        "investigation_findings": [
            {
                "title": "Correlated alert cluster",
                "detail": "Multiple alerts share indicators within the correlation window.",
                "evidence_ids": evidence_ids,
            }
        ],
        "uncertainties": ["Attacker intent is not established by the evidence."],
        "recommended_next_steps": ["Review the affected hosts with analyst approval."],
        "confidence": 0.7,
    }
    return json.dumps(report)


@pytest.fixture
def no_llm_config(monkeypatch):
    """Ensure no LLM provider is configured."""
    monkeypatch.setattr(settings, "LLM_PROVIDER", None)
    monkeypatch.setattr(settings, "LLM_API_KEY", None)


@pytest.fixture
def incident_with_alerts(db_session):
    """A correlated multi-alert incident built directly in the test DB."""
    now = datetime.now(timezone.utc)
    _make_alert(
        db_session,
        rule_name="Brute Force",
        severity="high",
        event_type="failed_login",
        payload={"src_ip": "10.0.0.5", "dst_ip": "198.51.100.1", "user": "admin", "host": "ws-01"},
        timestamp=now,
    )
    _make_alert(
        db_session,
        rule_name="Privilege Escalation",
        severity="high",
        event_type="privilege_escalation",
        payload={"src_ip": "10.0.0.5", "dst_ip": "198.51.100.1", "user": "admin", "host": "ws-01"},
        timestamp=now + timedelta(minutes=2),
    )
    db_session.commit()
    engine = CorrelationEngine(db_session)
    return engine.correlate()[0]


def _build_context(db_session, incident) -> Any:
    alerts = CorrelationService.get_incident_alerts(db_session, incident.id)
    risk = RiskService.get_risk(db_session, incident.id)
    timeline = TimelineService.get_timeline(db_session, incident.id)
    events_by_alert = {a.id: a.event for a in alerts}
    return build_investigation_context(incident, alerts, timeline, risk, events_by_alert)


def _api_incident(client) -> str:
    """Create a multi-alert incident through the public API; return its id."""
    client.post("/api/v1/rules/", json={
        "name": "AI Test Rule",
        "rule_type": "pattern_match",
        "severity": "high",
        "conditions": {"type": "pattern_match", "field": "event_type", "pattern": "failed_login"},
        "enabled": True,
    })
    for _ in range(3):
        client.post("/api/v1/events/", json={
            "source": "test",
            "event_type": "failed_login",
            "severity": "high",
            "payload": {"src_ip": "10.0.0.5", "dst_ip": "198.51.100.1", "user": "admin", "host": "ws-01"},
        })
    corr = client.post("/api/v1/incidents/correlate").json()
    assert corr["incident_ids"], "expected at least one incident"
    return corr["incident_ids"][0]


def _use_provider(monkeypatch, provider: FakeProvider) -> FakeProvider:
    monkeypatch.setattr("app.ai.service.get_provider", lambda: provider)
    return provider


class TestInvestigateAPI:
    """Scenario 1-3, 5, 6, 9: error paths and graceful degradation."""

    def test_missing_incident_returns_404(self, client):
        resp = client.post("/api/v1/incidents/does-not-exist/investigate")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Incident not found"

    def test_missing_llm_configuration_returns_clear_error(self, client, no_llm_config):
        incident_id = _api_incident(client)
        resp = client.post(f"/api/v1/incidents/{incident_id}/investigate")
        assert resp.status_code == 400
        detail = resp.json()["detail"]
        assert "not configured" in detail
        assert "LLM_API_KEY" in detail
        assert "demo" in detail

    def test_provider_failure_returns_graceful_error(self, client, monkeypatch):
        incident_id = _api_incident(client)
        _use_provider(
            monkeypatch,
            FakeProvider(error=AIProviderError("AI provider returned HTTP 500")),
        )
        resp = client.post(f"/api/v1/incidents/{incident_id}/investigate")
        assert resp.status_code == 502
        assert "AI provider" in resp.json()["detail"]

    def test_provider_timeout_returns_504(self, client, monkeypatch):
        incident_id = _api_incident(client)
        _use_provider(
            monkeypatch,
            FakeProvider(error=AIProviderTimeoutError("AI provider did not respond within 60 seconds")),
        )
        resp = client.post(f"/api/v1/incidents/{incident_id}/investigate")
        assert resp.status_code == 504

    def test_malformed_json_response_rejected(self, client, monkeypatch):
        incident_id = _api_incident(client)
        _use_provider(monkeypatch, FakeProvider(response="this is not json {{{"))
        resp = client.post(f"/api/v1/incidents/{incident_id}/investigate")
        assert resp.status_code == 502
        body = resp.json()["detail"]
        assert "not valid JSON" in body["message"]

    def test_schema_invalid_response_rejected(self, client, monkeypatch):
        incident_id = _api_incident(client)
        incomplete = {"incident_summary": "only one field"}
        _use_provider(monkeypatch, FakeProvider(response=json.dumps(incomplete)))
        resp = client.post(f"/api/v1/incidents/{incident_id}/investigate")
        assert resp.status_code == 502
        body = resp.json()["detail"]
        assert "schema" in body["message"]
        assert body["validation_errors"]

    def test_unsupported_evidence_id_rejected(self, client, monkeypatch):
        incident_id = _api_incident(client)
        report = json.loads(valid_report_for({"alerts": [], "potential_attack_stages": []}))
        report["investigation_findings"][0]["evidence_ids"] = [
            "alert-made-up",
            "event-also-fake",
        ]
        _use_provider(monkeypatch, FakeProvider(response=json.dumps(report)))
        resp = client.post(f"/api/v1/incidents/{incident_id}/investigate")
        assert resp.status_code == 502
        body = resp.json()["detail"]
        assert "not supplied" in body["message"]
        assert set(body["unsupported_evidence_ids"]) == {"alert-made-up", "event-also-fake"}

    def test_context_too_large_returns_413(self, client, monkeypatch, no_llm_config):
        incident_id = _api_incident(client)
        monkeypatch.setattr(settings, "LLM_MAX_CONTEXT_CHARS", 10)
        _use_provider(monkeypatch, FakeProvider(response=valid_report_for))
        resp = client.post(f"/api/v1/incidents/{incident_id}/investigate")
        assert resp.status_code == 413
        assert "too large" in resp.json()["detail"]

    def test_existing_functionality_unaffected_without_ai(self, client, no_llm_config):
        incident_id = _api_incident(client)
        assert client.get("/health").status_code == 200
        assert client.get("/api/v1/events/").status_code == 200
        assert client.get("/api/v1/incidents/").status_code == 200
        assert client.get(f"/api/v1/incidents/{incident_id}/risk").status_code == 200
        assert client.get(f"/api/v1/incidents/{incident_id}/timeline").status_code == 200
        # AI endpoint fails clearly, everything else keeps working
        assert client.post(f"/api/v1/incidents/{incident_id}/investigate").status_code == 400

    def test_get_investigation_before_any_run_returns_404(self, client, no_llm_config):
        incident_id = _api_incident(client)
        resp = client.get(f"/api/v1/incidents/{incident_id}/investigation")
        assert resp.status_code == 404
        assert "No investigation" in resp.json()["detail"]

    def test_get_investigation_missing_incident_returns_404(self, client):
        resp = client.get("/api/v1/incidents/does-not-exist/investigation")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Incident not found"


class TestInvestigationFlow:
    """Scenarios 4, 7, 10: valid responses, evidence isolation, full flow."""

    def test_valid_response_accepted_and_persisted(self, client, monkeypatch):
        incident_id = _api_incident(client)
        provider = _use_provider(monkeypatch, FakeProvider(response=valid_report_for))

        resp = client.post(f"/api/v1/incidents/{incident_id}/investigate")
        assert resp.status_code == 200
        data = resp.json()
        assert data["incident_id"] == incident_id
        assert data["provider"] == "fake"
        assert data["analysis_mode"] == "live"
        assert data["evidence_ids"]
        report = data["investigation"]
        for field in (
            "incident_summary",
            "threat_assessment",
            "evidence",
            "attack_narrative",
            "potential_attack_stages",
            "affected_entities",
            "investigation_findings",
            "uncertainties",
            "recommended_next_steps",
            "confidence",
        ):
            assert field in report
        assert 0.0 <= report["confidence"] <= 1.0

        # GET returns the persisted investigation
        get_resp = client.get(f"/api/v1/incidents/{incident_id}/investigation")
        assert get_resp.status_code == 200
        assert get_resp.json()["generated_at"] == data["generated_at"]

    def test_ai_receives_only_intended_structured_evidence(self, client, monkeypatch):
        incident_id = _api_incident(client)
        provider = _use_provider(monkeypatch, FakeProvider(response=valid_report_for))

        resp = client.post(f"/api/v1/incidents/{incident_id}/investigate")
        assert resp.status_code == 200
        assert provider.contexts, "provider should have been called"

        context = provider.contexts[0]
        assert set(context.keys()) <= ALLOWED_CONTEXT_KEYS
        for key in ("incident", "alerts", "timeline", "observed_entities"):
            assert key in context

        for alert in context["alerts"]:
            assert set(alert.keys()) <= ALLOWED_ALERT_KEYS

        serialized = json.dumps(context, default=str).lower()
        for forbidden in ("api_key", "secret", "password", "database_url", "rule_id"):
            assert forbidden not in serialized, f"context leaks '{forbidden}'"

    def test_complete_flow_with_mocked_provider(self, client, monkeypatch):
        incident_id = _api_incident(client)
        provider = _use_provider(monkeypatch, FakeProvider(response=valid_report_for))

        resp = client.post(f"/api/v1/incidents/{incident_id}/investigate")
        assert resp.status_code == 200
        data = resp.json()

        report = data["investigation"]
        assert report["investigation_findings"], "findings must be present"
        cited = set()
        for finding in report["investigation_findings"]:
            assert finding["evidence_ids"], "each finding must cite evidence"
            cited.update(finding["evidence_ids"])
        assert cited
        assert cited <= set(data["evidence_ids"]), "citations must reference supplied evidence"
        assert report["uncertainties"]
        assert report["recommended_next_steps"]
        assert report["attack_narrative"]

        # Re-running replaces the investigation (most recent wins)
        again = client.post(f"/api/v1/incidents/{incident_id}/investigate")
        assert again.status_code == 200
        stored = client.get(f"/api/v1/incidents/{incident_id}/investigation")
        assert stored.status_code == 200
        assert stored.json()["generated_at"] == again.json()["generated_at"]

    def test_demo_mode_end_to_end(self, client, monkeypatch):
        """LLM_PROVIDER=demo resolves to the deterministic demo provider."""
        monkeypatch.setattr(settings, "LLM_PROVIDER", "demo")
        incident_id = _api_incident(client)

        resp = client.post(f"/api/v1/incidents/{incident_id}/investigate")
        assert resp.status_code == 200
        data = resp.json()
        assert data["provider"] == "demo"
        assert data["analysis_mode"].startswith("DEMO")
        report = data["investigation"]
        assert report["incident_summary"]
        assert report["uncertainties"][0].startswith("This report was generated by the deterministic DEMO/MOCK provider")
        cited = set()
        for finding in report["investigation_findings"]:
            cited.update(finding["evidence_ids"])
        assert cited <= set(data["evidence_ids"])


class TestPrompts:
    """Scenario 8: the prompt explicitly forbids fabrication."""

    def test_system_prompt_forbids_fabrication(self):
        prompt = SYSTEM_PROMPT
        assert "OBSERVED EVIDENCE" in prompt
        assert "Do NOT invent" in prompt
        assert "ONLY from the supplied evidence" in prompt
        assert "never" in prompt.lower()
        assert "confirmed" in prompt  # must not claim confirmed attacks
        assert "insufficient" in prompt

    def test_system_prompt_forbids_autonomous_actions(self):
        prompt = SYSTEM_PROMPT
        assert "do NOT execute commands" in prompt
        assert "analysis and recommendations ONLY" in prompt

    def test_system_prompt_specifies_exact_output_contract(self):
        for field in (
            "incident_summary",
            "threat_assessment",
            "evidence",
            "attack_narrative",
            "potential_attack_stages",
            "affected_entities",
            "investigation_findings",
            "uncertainties",
            "recommended_next_steps",
            "confidence",
        ):
            assert f'"{field}"' in SYSTEM_PROMPT

    def test_user_prompt_wraps_evidence_and_demands_json_only(self):
        context = {"incident": {"id": "inc-1"}, "alerts": []}
        user_prompt = build_user_prompt(context)
        assert "=== OBSERVED EVIDENCE" in user_prompt
        assert "END OF OBSERVED EVIDENCE" in user_prompt
        assert "JSON object only" in user_prompt
        assert "inc-1" in user_prompt

        messages = build_messages(context)
        assert [m["role"] for m in messages] == ["system", "user"]
        assert messages[0]["content"] == SYSTEM_PROMPT


class TestValidation:
    def test_code_fenced_json_is_accepted(self, db_session, incident_with_alerts):
        context = _build_context(db_session, incident_with_alerts)
        raw = "```json\n" + valid_report_for(context.payload) + "\n```"
        report = parse_and_validate(raw, context)
        assert report.incident_summary

    def test_confidence_percentage_normalised(self):
        context = InvestigationContext(payload={})

        report = parse_and_validate(
            json.dumps({
                "incident_summary": "s", "threat_assessment": "t", "evidence": [],
                "attack_narrative": "n", "potential_attack_stages": [],
                "affected_entities": [], "investigation_findings": [],
                "uncertainties": [], "recommended_next_steps": [],
                "confidence": 85,
            }),
            context,
        )
        assert report.confidence == 0.85

    def test_empty_response_rejected(self):
        with pytest.raises(AIResponseValidationError):
            parse_and_validate("   ", InvestigationContext(payload={}))

    def test_non_object_json_rejected(self):
        with pytest.raises(AIResponseValidationError, match="not a JSON object"):
            parse_and_validate('["a", "list"]', InvestigationContext(payload={}))

    def test_unsupported_citation_rejected_with_ids(self, db_session, incident_with_alerts):
        context = _build_context(db_session, incident_with_alerts)
        raw = valid_report_for(context.payload)
        report = json.loads(raw)
        report["investigation_findings"][0]["evidence_ids"] = ["alert-ghost"]
        with pytest.raises(AIEvidenceValidationError) as exc_info:
            parse_and_validate(json.dumps(report), context)
        assert exc_info.value.unsupported_ids == ["alert-ghost"]


class TestContextBuilder:
    def test_context_contains_expected_evidence(self, db_session, incident_with_alerts):
        context = _build_context(db_session, incident_with_alerts)
        assert len(context.payload["alerts"]) == 2
        alert_ids = {a["id"] for a in context.payload["alerts"]}
        assert alert_ids == {
            f"alert-{aid}" for aid in incident_with_alerts.alert_ids
        }
        assert context.payload["deterministic_risk_assessment"]["risk_level"]
        assert context.payload["potential_attack_stages"]
        assert not context.truncated

    def test_context_truncation_limits_citable_evidence(self, db_session, incident_with_alerts):
        alerts = CorrelationService.get_incident_alerts(db_session, incident_with_alerts.id)
        risk = RiskService.get_risk(db_session, incident_with_alerts.id)
        timeline = TimelineService.get_timeline(db_session, incident_with_alerts.id)
        events_by_alert = {a.id: a.event for a in alerts}

        context = build_investigation_context(
            incident_with_alerts, alerts, timeline, risk,
            events_by_alert=events_by_alert, max_alerts=1,
        )
        assert context.truncated
        assert len(context.payload["alerts"]) == 1
        assert context.payload["context_notes"]["alerts_truncated"] is True
        # IDs of the dropped alert are no longer citable
        included = {a["id"] for a in context.payload["alerts"]}
        dropped = {f"alert-{aid}" for aid in incident_with_alerts.alert_ids} - included
        assert dropped
        assert not (dropped & context.evidence_ids)

    def test_context_too_large_raises(self, db_session, incident_with_alerts):
        alerts = CorrelationService.get_incident_alerts(db_session, incident_with_alerts.id)
        risk = RiskService.get_risk(db_session, incident_with_alerts.id)
        timeline = TimelineService.get_timeline(db_session, incident_with_alerts.id)
        events_by_alert = {a.id: a.event for a in alerts}

        with pytest.raises(AIContextTooLargeError):
            build_investigation_context(
                incident_with_alerts, alerts, timeline, risk,
                events_by_alert=events_by_alert, max_context_chars=10,
            )

    def test_ml_anomaly_included_when_present(self, db_session):
        now = datetime.now(timezone.utc)
        _make_alert(
            db_session,
            rule_name="ML Rule",
            severity="medium",
            event_type="odd_behavior",
            payload={
                "src_ip": "10.0.0.9",
                "host": "ws-02",
                "anomaly_score": 0.92,
                "is_anomaly": True,
                "confidence": 0.88,
                "reason": "Unusual process execution pattern",
            },
            timestamp=now,
        )
        db_session.commit()
        incident = CorrelationEngine(db_session).correlate()[0]

        context = _build_context(db_session, incident)
        ml_alerts = [a for a in context.payload["alerts"] if a["ml_anomaly"]]
        assert ml_alerts
        assert ml_alerts[0]["ml_anomaly"]["anomaly_score"] == 0.92


class TestDemoProvider:
    def test_demo_report_passes_full_validation(self, db_session, incident_with_alerts):
        context = _build_context(db_session, incident_with_alerts)
        provider = DemoInvestigatorProvider()
        raw = provider.investigate(context.payload)
        report = parse_and_validate(raw, context)
        assert report.incident_summary
        assert report.attack_narrative
        assert report.investigation_findings
        assert report.uncertainties
        assert report.recommended_next_steps
        assert 0 < report.confidence <= 1

    def test_demo_report_never_invents_entities(self, db_session, incident_with_alerts):
        context = _build_context(db_session, incident_with_alerts)
        report = json.loads(DemoInvestigatorProvider().investigate(context.payload))
        known_hosts = set(context.payload["observed_entities"]["hosts"])
        for entity in report["affected_entities"]:
            if entity.startswith("host: "):
                assert entity.split("host: ", 1)[1] in known_hosts
        # Narrative may only mention IPs that appear in the evidence
        evidence_ips = set()
        for alert in context.payload["alerts"]:
            for ip in (alert.get("source_ip"), alert.get("destination_ip")):
                if ip:
                    evidence_ips.add(ip)
        for word in report["attack_narrative"].split():
            cleaned = word.strip(".,")
            if cleaned.count(".") == 3 and all(p.isdigit() for p in cleaned.split(".")):
                assert cleaned in evidence_ips

    def test_demo_provider_is_deterministic(self, db_session, incident_with_alerts):
        context = _build_context(db_session, incident_with_alerts)
        provider = DemoInvestigatorProvider()
        assert provider.investigate(context.payload) == provider.investigate(context.payload)

    def test_demo_provider_handles_empty_incident(self):
        context = {
            "incident": {"title": "Empty", "severity": "info", "status": "open"},
            "alerts": [],
            "deterministic_risk_assessment": None,
            "potential_attack_stages": [],
            "observed_entities": {},
        }
        raw = DemoInvestigatorProvider().investigate(context)
        report = parse_and_validate(raw, InvestigationContext(payload={}))
        assert report.confidence == 0.2
        assert report.affected_entities == []
        assert report.investigation_findings == []
        assert "No alert evidence" in report.attack_narrative


class TestProviderFactory:
    def test_demo_provider_selected_when_configured(self, monkeypatch):
        monkeypatch.setattr(settings, "LLM_PROVIDER", "demo")
        assert isinstance(get_provider(), DemoInvestigatorProvider)

    def test_openai_provider_selected_when_key_present(self, monkeypatch):
        monkeypatch.setattr(settings, "LLM_PROVIDER", None)
        monkeypatch.setattr(settings, "LLM_API_KEY", "sk-test")
        provider = get_provider()
        assert isinstance(provider, OpenAICompatibleProvider)
        assert provider.model == settings.LLM_MODEL
        assert provider.base_url == settings.LLM_BASE_URL

    def test_explicit_openai_without_key_raises(self, monkeypatch):
        monkeypatch.setattr(settings, "LLM_PROVIDER", "openai")
        monkeypatch.setattr(settings, "LLM_API_KEY", None)
        with pytest.raises(AIProviderNotConfiguredError, match="LLM_API_KEY"):
            get_provider()

    def test_no_configuration_raises_clear_error(self, monkeypatch):
        monkeypatch.setattr(settings, "LLM_PROVIDER", None)
        monkeypatch.setattr(settings, "LLM_API_KEY", None)
        with pytest.raises(AIProviderNotConfiguredError, match="LLM_PROVIDER=demo"):
            get_provider()


class TestOpenAICompatibleProvider:
    def _provider(self, timeout=5.0):
        return OpenAICompatibleProvider(
            api_key="sk-test",
            model="test-model",
            base_url="https://api.test/v1/",
            timeout_seconds=timeout,
        )

    def test_successful_call_returns_content(self, monkeypatch):
        captured = {}

        def fake_post(url, json=None, headers=None, timeout=None):
            captured.update(url=url, json=json, headers=headers, timeout=timeout)
            return SimpleNamespace(
                status_code=200,
                json=lambda: {"choices": [{"message": {"content": '{"ok": true}'}}]},
            )

        monkeypatch.setattr("app.ai.providers.httpx.post", fake_post)
        result = self._provider().investigate({"incident": {"id": "x"}})

        assert result == '{"ok": true}'
        assert captured["url"] == "https://api.test/v1/chat/completions"
        assert captured["headers"]["Authorization"] == "Bearer sk-test"
        assert captured["json"]["model"] == "test-model"
        assert [m["role"] for m in captured["json"]["messages"]] == ["system", "user"]
        assert captured["json"]["temperature"] == 0.1
        assert captured["timeout"] == 5.0

    def test_http_error_raises_provider_error(self, monkeypatch):
        monkeypatch.setattr(
            "app.ai.providers.httpx.post",
            lambda url, **kwargs: SimpleNamespace(status_code=500, json=lambda: {}),
        )
        with pytest.raises(AIProviderError, match="HTTP 500"):
            self._provider().investigate({})

    def test_timeout_raises_timeout_error(self, monkeypatch):
        def fake_post(url, **kwargs):
            raise httpx.TimeoutException("timed out")

        monkeypatch.setattr("app.ai.providers.httpx.post", fake_post)
        with pytest.raises(AIProviderTimeoutError):
            self._provider(timeout=1.0).investigate({})

    def test_connection_error_raises_provider_error(self, monkeypatch):
        def fake_post(url, **kwargs):
            raise httpx.ConnectError("refused")

        monkeypatch.setattr("app.ai.providers.httpx.post", fake_post)
        with pytest.raises(AIProviderError, match="connection error"):
            self._provider().investigate({})

    def test_unexpected_structure_raises_provider_error(self, monkeypatch):
        monkeypatch.setattr(
            "app.ai.providers.httpx.post",
            lambda url, **kwargs: SimpleNamespace(status_code=200, json=lambda: {"unexpected": True}),
        )
        with pytest.raises(AIProviderError, match="unexpected response structure"):
            self._provider().investigate({})

    def test_empty_content_raises_provider_error(self, monkeypatch):
        monkeypatch.setattr(
            "app.ai.providers.httpx.post",
            lambda url, **kwargs: SimpleNamespace(
                status_code=200,
                json=lambda: {"choices": [{"message": {"content": "   "}}]},
            ),
        )
        with pytest.raises(AIProviderError, match="empty response"):
            self._provider().investigate({})

