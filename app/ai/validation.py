"""Validation of AI provider responses.

Every provider response — including the demo provider — passes through
``parse_and_validate``: JSON parsing, schema validation against
``InvestigationReport``, and evidence-citation checking against the IDs that
were actually supplied in the context.
"""

import json
from typing import Any, List

from pydantic import ValidationError

from app.ai.context_builder import InvestigationContext
from app.ai.errors import AIEvidenceValidationError, AIResponseValidationError
from app.ai.schemas import InvestigationReport


def _strip_code_fences(text: str) -> str:
    """Remove markdown code fences some models wrap around JSON."""
    stripped = text.strip()
    if stripped.startswith("```"):
        first_newline = stripped.find("\n")
        if first_newline != -1:
            stripped = stripped[first_newline + 1 :]
        if stripped.rstrip().endswith("```"):
            stripped = stripped.rstrip()[:-3]
    return stripped.strip()


def _extract_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise AIResponseValidationError(
            f"AI response is not valid JSON ({exc.msg} at line {exc.lineno}, "
            f"column {exc.colno})"
        ) from exc


def _validate_schema(data: Any) -> InvestigationReport:
    if not isinstance(data, dict):
        raise AIResponseValidationError(
            "AI response is not a JSON object as required"
        )
    try:
        return InvestigationReport.model_validate(data)
    except ValidationError as exc:
        details: List[str] = []
        for error in exc.errors():
            location = ".".join(str(part) for part in error.get("loc", ()))
            details.append(f"{location or 'root'}: {error.get('msg')}")
        raise AIResponseValidationError(
            "AI response does not match the required investigation schema",
            details=details,
        ) from exc


def _validate_evidence_citations(
    report: InvestigationReport, context: InvestigationContext
) -> None:
    cited = set()
    for finding in report.investigation_findings:
        cited.update(finding.evidence_ids)
    for item in report.evidence:
        cited.update(item.evidence_ids)

    unsupported = sorted(cited - context.evidence_ids)
    if unsupported:
        raise AIEvidenceValidationError(
            "AI response cites evidence IDs that were not supplied in the "
            f"investigation context: {', '.join(unsupported)}",
            unsupported_ids=unsupported,
        )


def parse_and_validate(
    raw_response: str, context: InvestigationContext
) -> InvestigationReport:
    """Parse raw provider text and validate it against the schema and evidence."""
    if not raw_response or not raw_response.strip():
        raise AIResponseValidationError("AI response was empty")

    data = _extract_json(_strip_code_fences(raw_response))
    report = _validate_schema(data)
    _validate_evidence_citations(report, context)
    return report
