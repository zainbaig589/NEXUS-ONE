"""Detection rule wrapper."""

from typing import Dict, Any
from app.detection.evaluators import evaluate_condition


class DetectionRule:
    """Represents a single detection rule."""

    def __init__(self, rule_id: str, name: str, rule_type: str, severity: str, 
                 conditions: Dict[str, Any], threshold: float = None):
        self.rule_id = rule_id
        self.name = name
        self.rule_type = rule_type
        self.severity = severity
        self.conditions = conditions
        self.threshold = threshold

    def matches(self, event_data: Dict[str, Any]) -> bool:
        """Check if the event matches this rule's conditions."""
        return evaluate_condition(event_data, self.conditions)

    @classmethod
    def from_db_model(cls, rule_model) -> "DetectionRule":
        """Create DetectionRule from SQLAlchemy Rule model."""
        return cls(
            rule_id=rule_model.id,
            name=rule_model.name,
            rule_type=rule_model.rule_type,
            severity=rule_model.severity,
            conditions=rule_model.conditions,
            threshold=rule_model.threshold,
        )
