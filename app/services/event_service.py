"""Event-related service operations."""

from sqlalchemy.orm import Session
from app.models.event import Event
from app.schemas import EventCreate
from app.services.event_normalizer import normalize_event_data


class EventService:
    @staticmethod
    def create_event(db: Session, event_data: EventCreate) -> Event:
        db_event = Event(**normalize_event_data(event_data))
        db.add(db_event)
        db.commit()
        db.refresh(db_event)
        return db_event

    @staticmethod
    def get_event(db: Session, event_id: str):
        return db.query(Event).filter(Event.id == event_id).first()

    @staticmethod
    def get_events(db: Session, skip: int = 0, limit: int = 100):
        return db.query(Event).offset(skip).limit(limit).all()

    @staticmethod
    def get_unprocessed_events(db: Session, limit: int = 100):
        return (
            db.query(Event)
            .filter(Event.processed == False)  # noqa: E712
            .limit(limit)
            .all()
        )
