"""Deterministic response recommendation layer.

Recommends advisory response actions for incidents. Priorities are computed
by a deterministic engine — no LLM decides execution safety, and no action
is ever executed automatically.
"""

from app.response.engine import (
    ADVISORY_NOTICE,
    PRIORITY_LEVELS,
    PRIORITY_WEIGHTS,
    RULE_BASE_SCORES,
    generate_recommendations,
    valid_evidence_ids,
)
from app.response.schemas import RecommendationsResponse, ResponseRecommendation

__all__ = [
    "ADVISORY_NOTICE",
    "PRIORITY_LEVELS",
    "PRIORITY_WEIGHTS",
    "RULE_BASE_SCORES",
    "generate_recommendations",
    "valid_evidence_ids",
    "RecommendationsResponse",
    "ResponseRecommendation",
]
