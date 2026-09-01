"""Rule-based detection engine."""

from typing import List, Dict, Any, Optional

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.rule import Rule
from app.detection.rules import DetectionRule
from app.services.ml_service import MLService


ML_SENTINEL_RULE_NAME = "ML Anomaly Detection"


class RuleEngine:
    """Evaluates security events against defined detection rules."""

    def __init__(self, db: Session):
        self.db = db
        self.rules: List[DetectionRule] = []

    def load_rules(self):
        """Load enabled detection rules from database."""
        db_rules = self.db.query(Rule).filter(Rule.enabled == True).all()
        self.rules = [DetectionRule.from_db_model(r) for r in db_rules]

    def evaluate(self, event_data: Dict[str, Any], event_id: str) -> List[Alert]:
        """Evaluate a single event against all loaded rules.
        
        Returns list of Alert objects for matched rules.
        """
        if not self.rules:
            self.load_rules()
        
        alerts = []
        for rule in self.rules:
            if rule.matches(event_data):
                alert = Alert(
                    event_id=event_id,
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    status="new",
                    description=f"Rule '{rule.name}' triggered",
                )
                alerts.append(alert)
        
        return alerts

    def process_event(self, event) -> List[Alert]:
        """Process an event through the detection engine.
        
        Args:
            event: SQLAlchemy Event model instance
            
        Returns:
            List of Alert objects created for this event
        """
        event_data = {
            "id": event.id,
            "source": event.source,
            "event_type": event.event_type,
            "severity": event.severity,
            "payload": event.payload,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        }

        alerts = self.evaluate(event_data, event.id)
        ml_alert = self._create_ml_alert(event)
        if ml_alert is not None:
            alerts.append(ml_alert)

        for alert in alerts:
            self.db.add(alert)

        event.processed = True
        self.db.commit()

        return alerts

    def _create_ml_alert(self, event) -> Optional[Alert]:
        existing_alert = (
            self.db.query(Alert)
            .filter(
                Alert.event_id == event.id,
                Alert.detection_source == "ml",
            )
            .first()
        )
        if existing_alert is not None:
            return None

        try:
            result = MLService.analyze(
                event.source,
                event.event_type,
                event.severity,
                event.payload,
                event.timestamp,
            )
        except Exception:
            return None

        if not result.get("is_anomaly"):
            return None

        rule = self._get_ml_sentinel_rule()
        return Alert(
            event_id=event.id,
            rule_id=rule.id,
            rule_name=rule.name,
            severity=_ml_alert_severity(result.get("severity")),
            status="new",
            description=result.get("reason"),
            detection_source="ml",
        )

    def _get_ml_sentinel_rule(self) -> Rule:
        rule = self.db.query(Rule).filter(Rule.name == ML_SENTINEL_RULE_NAME).first()
        if rule is not None:
            return rule

        rule = Rule(
            name=ML_SENTINEL_RULE_NAME,
            description="Disabled sentinel for persisted ML anomaly alerts.",
            rule_type="ml_anomaly",
            severity="medium",
            conditions={"type": "ml_anomaly"},
            enabled=False,
        )
        self.db.add(rule)
        self.db.flush()
        return rule


def _ml_alert_severity(value: Any) -> str:
    severity = str(value or "medium").strip().lower()
    return severity if severity in {"info", "low", "medium"} else "medium"
