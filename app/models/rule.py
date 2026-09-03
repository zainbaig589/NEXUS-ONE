import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, Boolean, JSON, Float
from app.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Rule(Base):
    __tablename__ = "rules"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False, unique=True)
    description = Column(String, nullable=True)
    rule_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    conditions = Column(JSON, nullable=False)
    threshold = Column(Float, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=_utcnow, nullable=False)
