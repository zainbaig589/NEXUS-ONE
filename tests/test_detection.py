"""Tests for the detection engine core."""

from app.detection.evaluators import (
    get_field_value,
    evaluate_threshold,
    evaluate_pattern_match,
    evaluate_combination,
    evaluate_condition,
)
from app.detection.rules import DetectionRule
from app.detection import RuleEngine
from app.models.event import Event
from app.models.rule import Rule
from app.models.alert import Alert
from app.services.ml_service import MLService


class TestGetFieldValue:
    def test_simple_field(self):
        data = {"event_type": "login", "source": "auth"}
        assert get_field_value(data, "event_type") == "login"

    def test_nested_field(self):
        data = {"payload": {"ip": "1.2.3.4", "port": 80}}
        assert get_field_value(data, "payload.ip") == "1.2.3.4"

    def test_deeply_nested_field(self):
        data = {"payload": {"user": {"name": "admin", "id": 42}}}
        assert get_field_value(data, "payload.user.id") == 42

    def test_missing_field(self):
        data = {"event_type": "login"}
        assert get_field_value(data, "payload.ip") is None

    def test_missing_nested_field(self):
        data = {"payload": {}}
        assert get_field_value(data, "payload.ip") is None


class TestEvaluateThreshold:
    def test_gt_true(self):
        data = {"payload": {"count": 10}}
        condition = {"field": "payload.count", "operator": "gt", "value": 5}
        assert evaluate_threshold(data, condition) is True

    def test_gt_false(self):
        data = {"payload": {"count": 3}}
        condition = {"field": "payload.count", "operator": "gt", "value": 5}
        assert evaluate_threshold(data, condition) is False

    def test_gte_equal(self):
        data = {"payload": {"count": 5}}
        condition = {"field": "payload.count", "operator": "gte", "value": 5}
        assert evaluate_threshold(data, condition) is True

    def test_lt_true(self):
        data = {"payload": {"count": 3}}
        condition = {"field": "payload.count", "operator": "lt", "value": 5}
        assert evaluate_threshold(data, condition) is True

    def test_eq_true(self):
        data = {"payload": {"count": 5}}
        condition = {"field": "payload.count", "operator": "eq", "value": 5}
        assert evaluate_threshold(data, condition) is True

    def test_neq_true(self):
        data = {"payload": {"count": 10}}
        condition = {"field": "payload.count", "operator": "neq", "value": 5}
        assert evaluate_threshold(data, condition) is True

    def test_missing_field_returns_false(self):
        data = {"payload": {}}
        condition = {"field": "payload.count", "operator": "gt", "value": 5}
        assert evaluate_threshold(data, condition) is False

    def test_invalid_operator_returns_false(self):
        data = {"payload": {"count": 10}}
        condition = {"field": "payload.count", "operator": "invalid", "value": 5}
        assert evaluate_threshold(data, condition) is False


class TestEvaluatePatternMatch:
    def test_exact_match(self):
        data = {"event_type": "failed_login"}
        condition = {"field": "event_type", "pattern": "failed_login"}
        assert evaluate_pattern_match(data, condition) is True

    def test_exact_match_false(self):
        data = {"event_type": "successful_login"}
        condition = {"field": "event_type", "pattern": "failed_login"}
        assert evaluate_pattern_match(data, condition) is False

    def test_regex_match(self):
        data = {"payload": {"ip": "10.0.1.55"}}
        condition = {"field": "payload.ip", "pattern": r"^10\.0\..*"}
        assert evaluate_pattern_match(data, condition) is True

    def test_regex_no_match(self):
        data = {"payload": {"ip": "192.168.1.1"}}
        condition = {"field": "payload.ip", "pattern": r"^10\.0\..*"}
        assert evaluate_pattern_match(data, condition) is False

    def test_missing_field_returns_false(self):
        data = {"event_type": "login"}
        condition = {"field": "payload.ip", "pattern": "1.2.3.4"}
        assert evaluate_pattern_match(data, condition) is False


class TestEvaluateCombination:
    def test_and_all_true(self):
        data = {"event_type": "failed_login", "payload": {"count": 10}}
        condition = {
            "logic": "and",
            "conditions": [
                {"type": "pattern_match", "field": "event_type", "pattern": "failed_login"},
                {"type": "threshold", "field": "payload.count", "operator": "gt", "value": 5},
            ],
        }
        assert evaluate_combination(data, condition) is True

    def test_and_one_false(self):
        data = {"event_type": "failed_login", "payload": {"count": 2}}
        condition = {
            "logic": "and",
            "conditions": [
                {"type": "pattern_match", "field": "event_type", "pattern": "failed_login"},
                {"type": "threshold", "field": "payload.count", "operator": "gt", "value": 5},
            ],
        }
        assert evaluate_combination(data, condition) is False

    def test_or_one_true(self):
        data = {"event_type": "failed_login", "payload": {"count": 2}}
        condition = {
            "logic": "or",
            "conditions": [
                {"type": "pattern_match", "field": "event_type", "pattern": "failed_login"},
                {"type": "threshold", "field": "payload.count", "operator": "gt", "value": 5},
            ],
        }
        assert evaluate_combination(data, condition) is True

    def test_or_all_false(self):
        data = {"event_type": "login", "payload": {"count": 2}}
        condition = {
            "logic": "or",
            "conditions": [
                {"type": "pattern_match", "field": "event_type", "pattern": "failed_login"},
                {"type": "threshold", "field": "payload.count", "operator": "gt", "value": 5},
            ],
        }
        assert evaluate_combination(data, condition) is False

    def test_empty_conditions(self):
        condition = {"logic": "and", "conditions": []}
        assert evaluate_combination({}, condition) is False


class TestDetectionRule:
    def test_rule_matches_event(self):
        rule = DetectionRule(
            rule_id="r1",
            name="Test Rule",
            rule_type="pattern_match",
            severity="high",
            conditions={"type": "pattern_match", "field": "event_type", "pattern": "failed_login"},
        )
        assert rule.matches({"event_type": "failed_login"}) is True
        assert rule.matches({"event_type": "success"}) is False

    def test_rule_from_db_model(self, db_session):
        db_rule = Rule(
            name="DB Rule",
            rule_type="threshold",
            severity="medium",
            conditions={"type": "threshold", "field": "payload.count", "operator": "gt", "value": 10},
        )
        db_session.add(db_rule)
        db_session.commit()
        db_session.refresh(db_rule)

        detection_rule = DetectionRule.from_db_model(db_rule)
        assert detection_rule.rule_id == db_rule.id
        assert detection_rule.name == "DB Rule"
        assert detection_rule.severity == "medium"


class TestRuleEngine:
    def _create_rule(self, db_session, name, conditions, severity="high"):
        rule = Rule(
            name=name,
            rule_type="pattern_match",
            severity=severity,
            conditions=conditions,
            enabled=True,
        )
        db_session.add(rule)
        db_session.commit()
        return rule

    def test_evaluate_matching_event(self, db_session):
        self._create_rule(
            db_session,
            "Failed Login Rule",
            {"type": "pattern_match", "field": "event_type", "pattern": "failed_login"},
        )

        engine = RuleEngine(db_session)
        engine.load_rules()
        assert len(engine.rules) == 1

        alerts = engine.evaluate(
            {"event_type": "failed_login", "payload": {}}, "event-1"
        )
        assert len(alerts) == 1
        assert alerts[0].rule_name == "Failed Login Rule"
        assert alerts[0].severity == "high"

    def test_evaluate_non_matching_event(self, db_session):
        self._create_rule(
            db_session,
            "Failed Login Rule",
            {"type": "pattern_match", "field": "event_type", "pattern": "failed_login"},
        )

        engine = RuleEngine(db_session)
        engine.load_rules()

        alerts = engine.evaluate({"event_type": "success"}, "event-2")
        assert len(alerts) == 0

    def test_evaluate_against_multiple_rules(self, db_session):
        self._create_rule(
            db_session,
            "Rule A",
            {"type": "pattern_match", "field": "event_type", "pattern": "failed_login"},
        )
        self._create_rule(
            db_session,
            "Rule B",
            {"type": "pattern_match", "field": "event_type", "pattern": "failed_login"},
            severity="critical",
        )

        engine = RuleEngine(db_session)
        engine.load_rules()
        alerts = engine.evaluate({"event_type": "failed_login"}, "event-3")
        assert len(alerts) == 2

    def test_disabled_rules_are_not_loaded(self, db_session):
        enabled = Rule(
            name="Enabled Rule",
            rule_type="pattern_match",
            severity="high",
            conditions={"type": "pattern_match", "field": "event_type", "pattern": ".*"},
            enabled=True,
        )
        disabled = Rule(
            name="Disabled Rule",
            rule_type="pattern_match",
            severity="high",
            conditions={"type": "pattern_match", "field": "event_type", "pattern": ".*"},
            enabled=False,
        )
        db_session.add_all([enabled, disabled])
        db_session.commit()

        engine = RuleEngine(db_session)
        engine.load_rules()
        assert len(engine.rules) == 1
        assert engine.rules[0].name == "Enabled Rule"

    def test_process_event_creates_alerts_and_marks_processed(self, db_session, monkeypatch):
        monkeypatch.setattr(
            MLService,
            "analyze",
            lambda *args, **kwargs: {"is_anomaly": False},
        )
        self._create_rule(
            db_session,
            "Test Rule",
            {"type": "pattern_match", "field": "event_type", "pattern": "alert_me"},
        )

        event = Event(
            source="test",
            event_type="alert_me",
            severity="low",
            payload={"key": "value"},
        )
        db_session.add(event)
        db_session.commit()
        db_session.refresh(event)

        engine = RuleEngine(db_session)
        alerts = engine.process_event(event)

        assert len(alerts) == 1
        assert alerts[0].rule_name == "Test Rule"
        assert event.processed is True

        # Verify alert is persisted
        db_alerts = db_session.query(Alert).all()
        assert len(db_alerts) == 1

    def test_process_event_no_match_marks_processed(self, db_session, monkeypatch):
        monkeypatch.setattr(
            MLService,
            "analyze",
            lambda *args, **kwargs: {"is_anomaly": False},
        )
        self._create_rule(
            db_session,
            "Test Rule",
            {"type": "pattern_match", "field": "event_type", "pattern": "alert_me"},
        )

        event = Event(
            source="test",
            event_type="normal_event",
            severity="low",
            payload={},
        )
        db_session.add(event)
        db_session.commit()
        db_session.refresh(event)

        engine = RuleEngine(db_session)
        alerts = engine.process_event(event)

        assert len(alerts) == 0
        assert event.processed is True
