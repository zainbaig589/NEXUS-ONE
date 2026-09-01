"""Pydantic schemas for structured incident reports.

The report deliberately separates three kinds of content so a reader can
never mistake analysis for fact:

- ``observed_evidence``  — what Nexus One actually recorded
- ``analysis``           — deterministic scoring + advisory AI narrative
- ``recommended_actions``— advisory actions requiring analyst approval
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.ai.schemas import InvestigationReport
from app.response.schemas import ResponseRecommendation

REPORT_FORMAT_VERSION = "1.0"

ANALYSIS_NOTICE = (
    "This section combines deterministic scoring (risk, attack stages) with an "
    "advisory AI investigation narrative. Statements from the AI investigation "
    "are analysis and inference, not confirmed facts; attack stages are labelled "
    "'Potential stage' for the same reason."
)


class ReportIncidentInfo(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    incident_id: str
    title: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    duration_seconds: int = 0
    alert_count: int = 0
    correlation_score: Optional[float] = None
    correlation_reasons: List[str] = Field(default_factory=list)


class ReportAlertSummary(BaseModel):
    """One correlated alert as observed evidence, with its citation IDs."""

    model_config = ConfigDict(str_strip_whitespace=True)

    alert_id: Optional[str] = None
    event_id: Optional[str] = None
    evidence_ids: List[str] = Field(default_factory=list)
    timestamp: Optional[str] = None
    event_type: Optional[str] = None
    rule_name: Optional[str] = None
    severity: Optional[str] = None
    detection_method: Optional[str] = None
    description: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    potential_attack_stage: Optional[str] = None


class ReportTimelineEntry(BaseModel):
    timestamp: Optional[str] = None
    event_id: Optional[str] = None
    alert_id: Optional[str] = None
    event_type: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    severity: Optional[str] = None
    detection_method: Optional[str] = None
    description: Optional[str] = None
    stage: Optional[str] = None


class ReportTimeline(BaseModel):
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    duration_seconds: int = 0
    entries: List[ReportTimelineEntry] = Field(default_factory=list)


class ReportObservedEvidence(BaseModel):
    """Section 1 — facts recorded by Nexus One."""

    incident: ReportIncidentInfo
    affected_users: List[str] = Field(default_factory=list)
    affected_hosts: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)
    destination_ips: List[str] = Field(default_factory=list)
    correlated_alerts: List[ReportAlertSummary] = Field(default_factory=list)
    detection_methods: List[str] = Field(default_factory=list)
    attack_timeline: ReportTimeline = Field(default_factory=ReportTimeline)


class ReportInvestigationMetadata(BaseModel):
    provider: str
    analysis_mode: str
    generated_at: str
    confidence: Optional[float] = None


class ReportAnalysis(BaseModel):
    """Section 2 — deterministic scoring plus advisory AI narrative."""

    analysis_notice: str
    deterministic_risk_assessment: Optional[Dict[str, Any]] = None
    potential_attack_stages: List[str] = Field(default_factory=list)
    ai_investigation: Optional[InvestigationReport] = None
    investigation_metadata: Optional[ReportInvestigationMetadata] = None
    investigation_status: str = "not_run"
    uncertainties: List[str] = Field(default_factory=list)


class ReportRecommendedActions(BaseModel):
    """Section 3 — advisory actions; nothing is executed automatically."""

    advisory_notice: str
    all_actions_require_analyst_approval: bool = True
    recommendations: List[ResponseRecommendation] = Field(default_factory=list)


class IncidentReport(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    report_id: str
    incident_id: str
    generated_at: str
    format_version: str = REPORT_FORMAT_VERSION
    title: str
    report_summary: str
    evidence_references: List[str] = Field(default_factory=list)
    observed_evidence: ReportObservedEvidence
    analysis: ReportAnalysis
    recommended_actions: ReportRecommendedActions
