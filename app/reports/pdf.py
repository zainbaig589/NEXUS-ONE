"""Renders an IncidentReport as a professional PDF document.

Uses fpdf2 (pure Python) to generate a branded, multi-page PDF with
cover page, section hierarchy, tables, severity indicators, and the
evidence integrity statement.
"""

from typing import Any, List, Optional

from fpdf import FPDF

from app.reports.schemas import IncidentReport


_SEVERITY_COLORS = {
    "CRITICAL": (192, 57, 43),
    "HIGH": (217, 138, 0),
    "MEDIUM": (31, 120, 193),
    "LOW": (127, 140, 141),
}

_BRAND_DARK = (22, 40, 63)
_BRAND_ACCENT = (31, 120, 193)
_TEXT_DARK = (30, 39, 51)
_TEXT_MUTED = (93, 109, 126)
_BG_LIGHT = (238, 242, 246)
_BORDER_LIGHT = (227, 232, 238)


class ReportPDF(FPDF):
    def __init__(self, report: IncidentReport):
        super().__init__()
        self.report = report
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*_TEXT_MUTED)
        self.cell(0, 6, "Nexus One Security Operations Platform", align="L")
        self.cell(0, 6, f"Report {self.report.report_id}", align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*_BORDER_LIGHT)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*_TEXT_MUTED)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def section_title(self, number: str, title: str):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*_BRAND_DARK)
        self.cell(0, 10, f"{number}. {title.upper()}", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*_BRAND_ACCENT)
        self.line(self.l_margin, self.get_y(), self.l_margin + 40, self.get_y())
        self.ln(4)

    def sub_heading(self, text: str):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*_TEXT_DARK)
        self.cell(0, 8, text, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def body_text(self, text: str):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*_TEXT_DARK)
        self.multi_cell(0, 5, _safe(text))
        self.ln(2)

    def muted_text(self, text: str):
        self.set_font("Helvetica", "I", 9)
        self.set_text_color(*_TEXT_MUTED)
        self.multi_cell(0, 5, _safe(text))
        self.ln(2)

    def badge(self, label: str, severity: Optional[str] = None):
        color = _SEVERITY_COLORS.get(severity or label.upper(), (100, 100, 100))
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        w = self.get_string_width(f" {label} ") + 4
        self.cell(w, 6, f" {label} ", fill=True, align="C")
        self.set_text_color(*_TEXT_DARK)

    def kv_row(self, key: str, value: Any):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*_TEXT_DARK)
        self.cell(50, 7, _safe(key) + ":")
        self.set_font("Helvetica", "", 10)
        self.cell(0, 7, _safe(value), new_x="LMARGIN", new_y="NEXT")

    def table_header(self, cols: List[tuple]):
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(*_BG_LIGHT)
        self.set_text_color(*_TEXT_DARK)
        for label, width in cols:
            self.cell(width, 7, label, border=1, fill=True, align="C")
        self.ln()

    def table_row(self, values: List[str], widths: List[float], severity_col: Optional[int] = None):
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*_TEXT_DARK)
        max_lines = 1
        for i, val in enumerate(values):
            lines = self.multi_cell(widths[i], 5, _safe(val), dry_run=True, output="LINES")
            max_lines = max(max_lines, len(lines))
        row_h = max(7, max_lines * 5)

        y_start = self.get_y()
        x_start = self.get_x()

        if y_start + row_h > self.h - 20:
            self.add_page()
            y_start = self.get_y()
            x_start = self.get_x()

        for i, val in enumerate(values):
            x = x_start + sum(widths[:i])
            self.set_xy(x, y_start)
            if severity_col is not None and i == severity_col:
                sev = val.upper()
                color = _SEVERITY_COLORS.get(sev, None)
                if color:
                    self.set_text_color(*color)
                    self.set_font("Helvetica", "B", 8)
            self.cell(widths[i], row_h, _safe(val), border=1)
            self.set_text_color(*_TEXT_DARK)
            self.set_font("Helvetica", "", 8)
        self.set_xy(x_start, y_start + row_h)


def _safe(value: Any) -> str:
    if value is None or value == "":
        return "-"
    text = str(value)
    return text.encode("latin-1", "replace").decode("latin-1")


def _build_cover(pdf: ReportPDF):
    r = pdf.report
    ev = r.observed_evidence
    inc = ev.incident
    risk = r.analysis.deterministic_risk_assessment or {}

    pdf.add_page()
    pdf.ln(30)

    pdf.set_font("Helvetica", "B", 32)
    pdf.set_text_color(*_BRAND_DARK)
    pdf.cell(0, 15, "NEXUS ONE", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_draw_color(*_BRAND_ACCENT)
    pdf.set_line_width(0.8)
    cx = pdf.w / 2
    pdf.line(cx - 30, pdf.get_y() + 2, cx + 30, pdf.get_y() + 2)
    pdf.ln(10)

    pdf.set_font("Helvetica", "", 16)
    pdf.set_text_color(*_TEXT_DARK)
    pdf.cell(0, 10, "SECURITY INCIDENT", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, "INVESTIGATION REPORT", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(15)

    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(*_TEXT_MUTED)

    details = [
        ("Incident", inc.title),
        ("Incident ID", inc.incident_id),
        ("Severity", inc.severity),
        ("Risk Score", f"{risk.get('risk_score', 'N/A')} ({risk.get('risk_level', 'N/A')})"),
        ("Investigation Date", r.generated_at),
        ("Report ID", r.report_id),
    ]
    for label, value in details:
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*_TEXT_DARK)
        pdf.cell(60, 8, f"{label}:", align="R")
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(*_TEXT_MUTED)
        pdf.cell(0, 8, f"  {_safe(value)}", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(20)
    pdf.set_font("Helvetica", "I", 10)
    pdf.set_text_color(*_TEXT_MUTED)
    pdf.cell(0, 8, "Generated by Nexus One Security Operations Platform", align="C")


def _build_executive_summary(pdf: ReportPDF):
    ai = pdf.report.analysis.ai_investigation
    pdf.add_page()
    pdf.section_title("1", "Executive Summary")
    if ai:
        pdf.body_text(ai.incident_summary)
    else:
        pdf.body_text(pdf.report.report_summary)


def _build_incident_overview(pdf: ReportPDF):
    ev = pdf.report.observed_evidence
    inc = ev.incident
    risk = pdf.report.analysis.deterministic_risk_assessment or {}

    pdf.ln(4)
    pdf.section_title("2", "Incident Overview")
    pdf.kv_row("Incident ID", inc.incident_id)
    pdf.kv_row("Title", inc.title)
    pdf.kv_row("Severity", inc.severity)
    pdf.kv_row("Risk Score", f"{risk.get('risk_score', 'N/A')} ({risk.get('risk_level', 'N/A')})")
    pdf.kv_row("Status", inc.status)
    pdf.kv_row("Alert Count", inc.alert_count)
    pdf.kv_row("First Seen", inc.first_seen)
    pdf.kv_row("Last Seen", inc.last_seen)
    if inc.duration_seconds is not None:
        pdf.kv_row("Duration", f"{inc.duration_seconds}s")
    pdf.kv_row("Correlation Score", inc.correlation_score)
    if ev.affected_users:
        pdf.kv_row("Affected Users", ", ".join(ev.affected_users))
    if ev.affected_hosts:
        pdf.kv_row("Affected Hosts", ", ".join(ev.affected_hosts))
    if ev.source_ips:
        pdf.kv_row("Source IPs", ", ".join(ev.source_ips))
    if ev.destination_ips:
        pdf.kv_row("Destination IPs", ", ".join(ev.destination_ips))
    if ev.detection_methods:
        pdf.kv_row("Detection Methods", ", ".join(ev.detection_methods))


def _build_threat_assessment(pdf: ReportPDF):
    an = pdf.report.analysis
    risk = an.deterministic_risk_assessment or {}

    pdf.add_page()
    pdf.section_title("3", "Threat Assessment")

    score = risk.get("risk_score")
    level = risk.get("risk_level", "UNKNOWN")
    if score is not None:
        pdf.set_font("Helvetica", "B", 28)
        sev_color = _SEVERITY_COLORS.get(level.upper(), _TEXT_DARK)
        pdf.set_text_color(*sev_color)
        pdf.cell(0, 16, f"{score}/100", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, level.upper(), align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(*_TEXT_DARK)
        pdf.ln(4)

    factors = risk.get("contributing_factors") or []
    if factors:
        pdf.sub_heading("Contributing Factors")
        for f in factors:
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(*_TEXT_DARK)
            pdf.cell(5, 5, "-")
            pdf.cell(0, 5, f"  {_safe(f)}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    explanation = risk.get("scoring_explanation")
    if explanation:
        pdf.sub_heading("Scoring Explanation")
        pdf.body_text(explanation)

    if an.potential_attack_stages:
        pdf.sub_heading("Attack Stages")
        for i, stage in enumerate(an.potential_attack_stages):
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*_BRAND_ACCENT)
            label = _safe(stage)
            pdf.cell(0, 7, f"  {i+1}. {label}", new_x="LMARGIN", new_y="NEXT")
            if i < len(an.potential_attack_stages) - 1:
                pdf.set_font("Helvetica", "", 10)
                pdf.set_text_color(*_TEXT_MUTED)
                pdf.cell(0, 5, "     |", new_x="LMARGIN", new_y="NEXT")
                pdf.cell(0, 5, "     v", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)


def _build_timeline(pdf: ReportPDF):
    ev = pdf.report.observed_evidence
    entries = ev.attack_timeline.entries

    pdf.add_page()
    pdf.section_title("4", "Attack Timeline")

    if not entries:
        pdf.body_text("No timeline entries available.")
        return

    cols = [("Time", 32), ("Event", 25), ("Severity", 18), ("Detection", 20), ("Description", 50), ("Evidence", 25)]
    widths = [w for _, w in cols]
    pdf.table_header(cols)
    for entry in entries:
        evidence = " ".join(entry.evidence_ids) if hasattr(entry, "evidence_ids") and entry.evidence_ids else (
            f"alert-{entry.alert_id}" if entry.alert_id else ""
        )
        pdf.table_row(
            [
                _fmt_ts(entry.timestamp),
                entry.event_type or "-",
                entry.severity or "-",
                entry.detection_method or "-",
                entry.description or "-",
                evidence,
            ],
            widths,
            severity_col=2,
        )


def _build_findings(pdf: ReportPDF):
    ai = pdf.report.analysis.ai_investigation
    pdf.add_page()
    pdf.section_title("5", "Key Findings")

    if not ai or not ai.investigation_findings:
        pdf.body_text("No findings were generated.")
        return

    for i, finding in enumerate(ai.investigation_findings):
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*_BRAND_ACCENT)
        pdf.cell(0, 8, f"FINDING {i+1:02d}", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*_TEXT_DARK)
        pdf.multi_cell(0, 5, _safe(finding.title))
        pdf.ln(1)

        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 5, _safe(finding.detail))
        pdf.ln(1)

        if finding.evidence_ids:
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(*_TEXT_MUTED)
            pdf.cell(0, 5, f"Evidence: {', '.join(finding.evidence_ids)}", new_x="LMARGIN", new_y="NEXT")

        pdf.set_draw_color(*_BORDER_LIGHT)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(4)


def _build_evidence_table(pdf: ReportPDF):
    ev = pdf.report.observed_evidence
    alerts = ev.correlated_alerts

    pdf.add_page()
    pdf.section_title("6", "Evidence")

    if not alerts:
        pdf.body_text("No correlated alert evidence available.")
        return

    cols = [
        ("Evidence ID", 25),
        ("Timestamp", 28),
        ("Event Type", 22),
        ("Rule", 22),
        ("Severity", 16),
        ("Detection", 18),
        ("Description", 39),
    ]
    widths = [w for _, w in cols]
    pdf.table_header(cols)
    for alert in alerts:
        evidence_id = " ".join(alert.evidence_ids) if alert.evidence_ids else "-"
        pdf.table_row(
            [
                evidence_id,
                _fmt_ts(alert.timestamp),
                alert.event_type or "-",
                alert.rule_name or "-",
                alert.severity or "-",
                alert.detection_method or "-",
                alert.description or "-",
            ],
            widths,
            severity_col=4,
        )


def _build_uncertainties(pdf: ReportPDF):
    an = pdf.report.analysis
    pdf.ln(6)
    pdf.section_title("7", "Uncertainties")

    if not an.uncertainties:
        pdf.body_text("No uncertainties were recorded.")
        return

    pdf.sub_heading("What We Cannot Confirm")
    for u in an.uncertainties:
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*_TEXT_DARK)
        pdf.cell(5, 5, "-")
        pdf.multi_cell(0, 5, f"  {_safe(u)}")
        pdf.ln(1)


def _build_next_steps(pdf: ReportPDF):
    ai = pdf.report.analysis.ai_investigation
    pdf.add_page()
    pdf.section_title("8", "Analyst Next Steps")

    if not ai or not ai.recommended_next_steps:
        pdf.body_text("No next steps were recommended.")
        return

    for i, step in enumerate(ai.recommended_next_steps):
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*_BRAND_ACCENT)
        num = f"{i+1:02d}"
        pdf.cell(10, 7, num)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*_TEXT_DARK)
        pdf.multi_cell(0, 5, _safe(step))
        pdf.ln(3)


def _build_recommendations(pdf: ReportPDF):
    ra = pdf.report.recommended_actions
    pdf.ln(4)
    pdf.section_title("9", "Recommendations")

    if not ra.recommendations:
        pdf.body_text("No recommendations were generated.")
        return

    for rec in ra.recommendations:
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*_TEXT_DARK)
        pdf.multi_cell(0, 6, _safe(rec.title))

        pdf.set_font("Helvetica", "B", 9)
        sev_color = _SEVERITY_COLORS.get(rec.priority.upper(), (100, 100, 100))
        pdf.set_text_color(*sev_color)
        pdf.cell(0, 5, rec.priority.upper(), new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*_TEXT_MUTED)
        pdf.cell(0, 5, f"Category: {rec.category}  |  Confidence: {rec.confidence}", new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*_TEXT_DARK)
        pdf.multi_cell(0, 5, _safe(rec.description))

        if rec.rationale:
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(*_TEXT_MUTED)
            pdf.multi_cell(0, 5, f"Rationale: {_safe(rec.rationale)}")

        if rec.evidence_ids:
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(*_TEXT_MUTED)
            pdf.cell(0, 5, f"Evidence: {', '.join(rec.evidence_ids)}", new_x="LMARGIN", new_y="NEXT")

        pdf.set_draw_color(*_BORDER_LIGHT)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(4)

    pdf.muted_text(ra.advisory_notice)


def _build_investigation_info(pdf: ReportPDF):
    meta = pdf.report.analysis.investigation_metadata
    pdf.ln(4)
    pdf.section_title("10", "Investigation Information")

    if meta:
        pdf.kv_row("Provider", meta.provider)
        pdf.kv_row("Analysis Mode", meta.analysis_mode)
        pdf.kv_row("Generated At", meta.generated_at)
        if meta.confidence is not None:
            pdf.kv_row("Confidence", f"{meta.confidence:.0%}")
    else:
        pdf.body_text("No AI investigation was attached to this report.")

    if meta and "DEMO" in (meta.analysis_mode or "").upper():
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(217, 138, 0)
        pdf.multi_cell(0, 5, "DEMO MODE - deterministic mock provider. Not a live LLM.")
        pdf.set_text_color(*_TEXT_DARK)


def _build_integrity_statement(pdf: ReportPDF):
    pdf.ln(8)
    pdf.set_draw_color(*_BRAND_ACCENT)
    pdf.set_line_width(0.5)
    y = pdf.get_y()
    pdf.rect(pdf.l_margin, y, pdf.w - pdf.l_margin - pdf.r_margin, 25)
    pdf.set_xy(pdf.l_margin + 4, y + 3)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*_BRAND_DARK)
    pdf.cell(0, 6, "EVIDENCE INTEGRITY", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(pdf.l_margin + 4)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*_TEXT_DARK)
    pdf.multi_cell(
        pdf.w - pdf.l_margin - pdf.r_margin - 8,
        4.5,
        "This report references evidence associated with the selected Nexus One incident. "
        "Findings should be validated by a security analyst before taking response actions.",
    )
    pdf.set_y(y + 28)


def _fmt_ts(value: Any) -> str:
    if value is None:
        return "-"
    text = str(value)
    if "T" in text:
        text = text.replace("T", " ")
    if len(text) > 19:
        text = text[:19]
    return text


def render_report_pdf(report: IncidentReport) -> bytes:
    """Render a validated IncidentReport as a professional PDF document."""
    pdf = ReportPDF(report)
    pdf.alias_nb_pages()

    _build_cover(pdf)
    _build_executive_summary(pdf)
    _build_incident_overview(pdf)
    _build_threat_assessment(pdf)
    _build_timeline(pdf)
    _build_findings(pdf)
    _build_evidence_table(pdf)
    _build_uncertainties(pdf)
    _build_next_steps(pdf)
    _build_recommendations(pdf)
    _build_investigation_info(pdf)
    _build_integrity_statement(pdf)

    return bytes(pdf.output())
