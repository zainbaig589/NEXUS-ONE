import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, Boolean, JSON
from app.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Event(Base):
    __tablename__ = "events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=_utcnow, nullable=False)
    source = Column(String, nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, index=True)
    payload = Column(JSON, nullable=False)
    processed = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=_utcnow, nullable=False)
