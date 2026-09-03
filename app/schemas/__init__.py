"""Pydantic schemas for request/response validation."""

from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.ai.schemas import InvestigationReport
from app.reports.schemas import IncidentReport
from app.response.schemas import RecommendationsResponse, ResponseRecommendation


class HealthResponse(BaseModel):
    status: str
    app_name: str
    version: str
    environment: str
    database: str
    ml_model: Optional[str] = None
    ai_provider: Optional[str] = None


class EventBase(BaseModel):
    source: str
    event_type: str
    severity: str = Field(..., pattern="^(info|low|medium|high|critical)$")
    payload: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, value):
        return value.strip().lower() if isinstance(value, str) else value


class EventCreate(EventBase):
    timestamp: Optional[datetime] = None


class EventResponse(EventBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    processed: bool
    created_at: datetime


class AlertBase(BaseModel):
    rule_name: str
    severity: str
    description: Optional[str] = None


class AlertCreate(AlertBase):
    event_id: str
    rule_id: str


class AlertResponse(AlertBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_id: str
    rule_id: str
    status: str
    detection_source: str = "rule"
    created_at: datetime


class IncidentBase(BaseModel):
    title: str
    severity: str
    description: Optional[str] = None


class IncidentCreate(IncidentBase):
    pass


class IncidentResponse(IncidentBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: str
    alert_ids: List[str] = Field(default_factory=list)
    alert_count: int
    correlation_score: Optional[float] = None
    correlation_reasons: List[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source_ips: List[str] = Field(default_factory=list)
    destination_ips: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    hosts: List[str] = Field(default_factory=list)
    risk_score: Optional[float] = None
    risk_level: str = "LOW"
    risk_factors: List[str] = Field(default_factory=list)
    attack_stages: List[str] = Field(default_factory=list)
    attack_timeline: Optional[List[TimelineEntry]] = None
    created_at: datetime
    updated_at: datetime


class CorrelationRequest(BaseModel):
    alert_ids: Optional[List[str]] = None
    threshold: Optional[float] = None
    time_window_minutes: Optional[int] = None


class CorrelationResponse(BaseModel):
    incidents_touched: int
    incidents_created: int
    incidents_updated: int
    incident_ids: List[str]


class RuleBase(BaseModel):
    name: str
    description: Optional[str] = None
    rule_type: str
    severity: str
    conditions: Dict[str, Any]
    threshold: Optional[float] = None
    enabled: bool = True


class RuleCreate(RuleBase):
    pass


class RuleResponse(RuleBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime


class PaginatedResponse(BaseModel):
    total: int
    items: List[Any]
    skip: int
    limit: int


class MLAnalyzeRequest(BaseModel):
    source: str
    event_type: str
    severity: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class MLAnalyzeResponse(BaseModel):
    anomaly_score: float
    is_anomaly: bool
    confidence: float
    severity: str
    reason: str
    features_used: List[str]
    detection_method: str = "isolation_forest"


class MLTrainResponse(BaseModel):
    status: str
    samples_trained: int
    model_path: str
    message: str


class MLStatusResponse(BaseModel):
    model_loaded: bool
    model_path: Optional[str]
    training_samples: Optional[int]
    features: List[str]
    threshold: float
    detection_method: str


class TimelineEntry(BaseModel):
    timestamp: Optional[datetime] = None
    event_id: Optional[str] = None
    alert_id: Optional[str] = None
    event_type: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    severity: str = "info"
    detection_method: str = "rule"
    description: Optional[str] = None
    stage: Optional[str] = None


class TimelineResponse(BaseModel):
    incident_id: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    duration_seconds: int = 0
    entries: List[TimelineEntry] = Field(default_factory=list)


class RiskResponse(BaseModel):
    incident_id: Optional[str] = None
    risk_score: float = 0.0
    risk_level: str = "LOW"
    contributing_factors: List[str] = Field(default_factory=list)
    scoring_explanation: str = ""


class IncidentSummaryResponse(BaseModel):
    incident: IncidentResponse
    risk: RiskResponse
    timeline: TimelineResponse
    potential_attack_stages: List[str] = Field(default_factory=list)
    related_alert_ids: List[str] = Field(default_factory=list)


class InvestigationResponse(BaseModel):
    """Envelope around the structured AI investigation report."""

    incident_id: str
    provider: str
    analysis_mode: str
    generated_at: str
    investigation: InvestigationReport
    evidence_ids: List[str] = Field(default_factory=list)
    context_truncated: bool = False
    risk_snapshot: Optional[Dict[str, Any]] = None
