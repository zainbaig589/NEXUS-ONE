"""AI-assisted incident investigation package.

Modular components:
- ``providers``: replaceable LLM provider abstraction + OpenAI-compatible
  implementation and factory
- ``demo_provider``: deterministic offline DEMO/MOCK provider
- ``context_builder``: evidence-only structured context construction
- ``prompts``: system/user prompt templates with no-fabrication rules
- ``schemas``: structured investigation response contract
- ``validation``: JSON/schema/evidence-citation validation
- ``service``: investigation orchestration (load → build → call → validate → persist)
- ``errors``: domain error types
"""

from app.ai.context_builder import InvestigationContext, build_investigation_context
from app.ai.errors import (
    AIEvidenceValidationError,
    AIInvestigationError,
    AIProviderError,
    AIProviderNotConfiguredError,
    AIProviderTimeoutError,
    AIResponseValidationError,
)
from app.ai.providers import LLMProvider, OpenAICompatibleProvider, get_provider
from app.ai.schemas import InvestigationReport
from app.ai.validation import parse_and_validate

_LAZY_EXPORTS = {"InvestigationService": "app.ai.service"}


def __getattr__(name):
    # Imported lazily: app.ai.service depends on app.services, which itself
    # imports app.schemas; a top-level import here would be circular for
    # anything importing app.schemas first.
    if name in _LAZY_EXPORTS:
        import importlib

        module = importlib.import_module(_LAZY_EXPORTS[name])
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "InvestigationContext",
    "build_investigation_context",
    "AIEvidenceValidationError",
    "AIInvestigationError",
    "AIProviderError",
    "AIProviderNotConfiguredError",
    "AIProviderTimeoutError",
    "AIResponseValidationError",
    "LLMProvider",
    "OpenAICompatibleProvider",
    "get_provider",
    "InvestigationReport",
    "InvestigationService",
    "parse_and_validate",
]
