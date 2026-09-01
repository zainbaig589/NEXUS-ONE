"""Pydantic schemas for the response recommendation layer."""

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ResponseRecommendation(BaseModel):
    """A single advisory response recommendation anchored to real evidence."""

    model_config = ConfigDict(str_strip_whitespace=True)

    recommendation_id: str
    title: str
    description: str
    priority: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    priority_score: float = Field(ge=0.0, le=100.0)
    priority_factors: List[str] = Field(default_factory=list)
    category: str
    rationale: str
    evidence_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    requires_analyst_approval: bool = True

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_confidence(cls, value):
        if isinstance(value, (int, float)) and value > 1.0:
            return value / 100.0
        return value


class RecommendationsResponse(BaseModel):
    """Envelope for the deterministic recommendations of one incident."""

    model_config = ConfigDict(str_strip_whitespace=True)

    incident_id: str
    generated_at: str
    advisory_notice: str
    risk_snapshot: Optional[Dict[str, Any]] = None
    recommendation_count: int = 0
    recommendations: List[ResponseRecommendation] = Field(default_factory=list)
