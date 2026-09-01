"""Structured incident reporting.

Assembles reports that clearly separate observed evidence, analysis
(deterministic + advisory AI narrative), and recommended actions.
JSON is the primary format; a clean HTML rendering is also provided.
"""

from app.reports.generator import build_incident_report
from app.reports.html import render_report_html
from app.reports.schemas import (
    ANALYSIS_NOTICE,
    REPORT_FORMAT_VERSION,
    IncidentReport,
)

__all__ = [
    "build_incident_report",
    "render_report_html",
    "ANALYSIS_NOTICE",
    "REPORT_FORMAT_VERSION",
    "IncidentReport",
]
