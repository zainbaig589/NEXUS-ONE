"""Incident-related service operations."""

from sqlalchemy.orm import Session
from app.models.incident import Incident
from app.schemas import IncidentCreate


class IncidentService:
    @staticmethod
    def create_incident(db: Session, incident_data: IncidentCreate, alert_ids: list = None) -> Incident:
        db_incident = Incident(**incident_data.model_dump(), alert_ids=alert_ids or [])
        db.add(db_incident)
        db.commit()
        db.refresh(db_incident)
        return db_incident

    @staticmethod
    def get_incident(db: Session, incident_id: str):
        return db.query(Incident).filter(Incident.id == incident_id).first()

    @staticmethod
    def get_incidents(db: Session, skip: int = 0, limit: int = 100):
        return (
            db.query(Incident)
            .order_by(Incident.created_at.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )
