"""Detection orchestration service."""

from dataclasses import dataclass
from typing import List

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import Event
from app.detection import RuleEngine


@dataclass
class DetectionBatchResult:
    alerts: List[Alert]
    processed_count: int


class DetectionService:
    @staticmethod
    def process_event(db: Session, event: Event) -> List[Alert]:
        """Run detection engine on a single event."""
        engine = RuleEngine(db)
        return engine.process_event(event)

    @staticmethod
    def process_unprocessed_events(db: Session, limit: int = 100) -> List[Alert]:
        """Process all unprocessed events through the detection engine."""
        return DetectionService.process_unprocessed_events_with_stats(db, limit).alerts

    @staticmethod
    def process_unprocessed_events_with_stats(
        db: Session, limit: int = 100
    ) -> DetectionBatchResult:
        """Process a batch and retain its selected event count."""
        unprocessed = (
            db.query(Event)
            .filter(Event.processed == False)  # noqa: E712
            .order_by(Event.created_at.asc())
            .limit(limit)
            .all()
        )

        all_alerts = []
        engine = RuleEngine(db)
        engine.load_rules()

        for event in unprocessed:
            all_alerts.extend(engine.process_event(event))

        return DetectionBatchResult(
            alerts=all_alerts,
            processed_count=len(unprocessed),
        )
