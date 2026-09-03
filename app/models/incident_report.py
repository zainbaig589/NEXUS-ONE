import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class IncidentReportRecord(Base):
    """Persisted snapshot of a generated incident report."""

    __tablename__ = "incident_reports"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=False, index=True)
    format_version = Column(String, default="1.0", nullable=False)
    content = Column(JSON, nullable=False)
    generated_at = Column(DateTime, default=_utcnow, nullable=False)

    incident = relationship("Incident", foreign_keys=[incident_id])
