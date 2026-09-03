"""Pydantic schemas for the demo attack-scenario endpoint."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class DemoStageResult(BaseModel):
    stage: str
    status: str  # "success" | "error" | "skipped"
    duration_ms: int = 0
    details: Dict[str, Any] = {}
    error: Optional[str] = None


class DemoAttackScenarioResponse(BaseModel):
    demo_run_id: str
    executed_at: datetime
    total_duration_ms: int = 0
    stages: List[DemoStageResult] = []
    events_created: int = 0
    alerts_created: int = 0
    rule_detections: int = 0
    ml_detections: int = 0
    incidents_created: int = 0
    incident_ids: List[str] = []
    primary_incident_id: Optional[str] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    investigation_status: str = "skipped"
    recommendation_count: int = 0
    report_generated: bool = False
    attack_stages: List[str] = []
