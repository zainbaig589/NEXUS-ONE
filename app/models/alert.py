import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String, ForeignKey("events.id"), nullable=False, index=True)
    rule_id = Column(String, ForeignKey("rules.id"), nullable=False, index=True)
    rule_name = Column(String, nullable=False)
    severity = Column(String, nullable=False, index=True)
    status = Column(String, default="new", nullable=False, index=True)
    description = Column(String, nullable=True)
    detection_source = Column(String, default="rule", nullable=False, index=True)
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True, index=True)
    created_at = Column(DateTime, default=_utcnow, nullable=False)

    event = relationship("Event", foreign_keys=[event_id])
    rule = relationship("Rule", foreign_keys=[rule_id])
    incident = relationship("Incident", foreign_keys=[incident_id])
