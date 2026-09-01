"""Pydantic schemas for the structured AI investigation response.

The LLM (or the demo provider) must produce a payload matching
``InvestigationReport``. Validation happens before anything is returned to
the caller or persisted.
"""

from typing import List

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EvidenceItem(BaseModel):
    """A piece of observed evidence the AI considered, with citations."""

    model_config = ConfigDict(str_strip_whitespace=True)

    description: str = Field(min_length=1)
    evidence_ids: List[str] = Field(default_factory=list)


class InvestigationFinding(BaseModel):
    """A single investigation finding, anchored to concrete evidence IDs."""

    model_config = ConfigDict(str_strip_whitespace=True)

    title: str = Field(min_length=1)
    detail: str = Field(min_length=1)
    evidence_ids: List[str] = Field(default_factory=list)


class InvestigationReport(BaseModel):
    """Structured output contract for an AI incident investigation."""

    model_config = ConfigDict(str_strip_whitespace=True)

    incident_summary: str = Field(min_length=1)
    threat_assessment: str = Field(min_length=1)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    attack_narrative: str = Field(min_length=1)
    potential_attack_stages: List[str] = Field(default_factory=list)
    affected_entities: List[str] = Field(default_factory=list)
    investigation_findings: List[InvestigationFinding] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)
    recommended_next_steps: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_confidence(cls, value):
        """Accept percentages (0-100) from the LLM and normalise to 0-1."""
        if isinstance(value, (int, float)) and value > 1.0:
            return value / 100.0
        return value
