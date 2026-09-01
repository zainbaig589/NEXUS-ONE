"""Alert-related service operations."""

from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.schemas import AlertCreate


class AlertService:
    @staticmethod
    def create_alert(db: Session, alert_data: AlertCreate) -> Alert:
        db_alert = Alert(**alert_data.model_dump())
        db.add(db_alert)
        db.commit()
        db.refresh(db_alert)
        return db_alert

    @staticmethod
    def get_alert(db: Session, alert_id: str):
        return db.query(Alert).filter(Alert.id == alert_id).first()

    @staticmethod
    def get_alerts(db: Session, skip: int = 0, limit: int = 100):
        return db.query(Alert).order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()
