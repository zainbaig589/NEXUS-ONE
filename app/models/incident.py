import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, Float, Integer, JSON
from app.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, index=True)
    status = Column(String, default="new", nullable=False, index=True)
    description = Column(String, nullable=True)

    # Correlation data
    alert_ids = Column(JSON, nullable=False, default=list)
    alert_count = Column(Integer, default=0, nullable=False)
    correlation_score = Column(Float, nullable=True)
    correlation_reasons = Column(JSON, nullable=True, default=list)

    # Temporal bounds (computed from alerts)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)

    # Indicator sets (extracted from correlated alerts)
    source_ips = Column(JSON, nullable=True, default=list)
    destination_ips = Column(JSON, nullable=True, default=list)
    users = Column(JSON, nullable=True, default=list)
    hosts = Column(JSON, nullable=True, default=list)

    # Risk scoring
    risk_score = Column(Float, default=0.0, nullable=False)
    risk_level = Column(String, default="LOW", nullable=False)
    risk_factors = Column(JSON, nullable=False, default=list)
    attack_stages = Column(JSON, nullable=False, default=list)

    # Future extensions (kept for later phases)
    attack_timeline = Column(JSON, nullable=True)
    ai_analysis = Column(JSON, nullable=True)
    response_recommendations = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=_utcnow, nullable=False)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)
