"""Renders an IncidentReport as a standalone, human-readable HTML document.

All dynamic values are HTML-escaped; the renderer never embeds unescaped
report content. The three report sections are visually separated and
labelled so observed evidence, analysis, and recommendations cannot be
confused.
"""

import html
from typing import Any, Dict, List, Optional

from app.reports.schemas import IncidentReport

_STYLE = """
body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #f4f6f8; color: #1e2733; }
.container { max-width: 1000px; margin: 0 auto; padding: 24px; }
header.report { background: #16283f; color: #fff; padding: 24px; border-radius: 8px 8px 0 0; }
header.report h1 { margin: 0 0 8px 0; font-size: 22px; }
header.report .meta { font-size: 12px; color: #b8c6d9; }
section { background: #fff; padding: 20px 24px; border-left: 5px solid #999; margin: 16px 0; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
section.evidence { border-left-color: #1f78c1; }
section.analysis { border-left-color: #d98a00; }
section.actions { border-left-color: #c0392b; }
section.summary { border-left-color: #16283f; }
h2 { font-size: 16px; margin: 0 0 12px 0; text-transform: uppercase; letter-spacing: 0.5px; }
h3 { font-size: 14px; margin: 16px 0 8px 0; color: #34495e; }
table { width: 100%; border-collapse: collapse; font-size: 12px; margin: 8px 0; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #e3e8ee; vertical-align: top; }
th { background: #eef2f6; color: #34495e; }
.notice { background: #fdf6e3; border: 1px solid #f0d9a8; padding: 10px 12px; font-size: 12px; border-radius: 4px; margin-bottom: 12px; }
.notice.actions { background: #fdeceb; border-color: #f2b8b5; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: bold; color: #fff; }
.badge.CRITICAL { background: #c0392b; } .badge.HIGH { background: #d98a00; }
.badge.MEDIUM { background: #1f78c1; } .badge.LOW { background: #7f8c8d; }
.rec { border: 1px solid #e3e8ee; border-radius: 6px; padding: 14px 16px; margin: 12px 0; }
.rec .rec-title { font-weight: bold; font-size: 14px; margin-bottom: 6px; }
.rec .rec-meta { font-size: 11px; color: #5d6d7e; margin-bottom: 8px; }
.rec .rec-field { font-size: 12px; margin: 4px 0; }
.rec .label { font-weight: bold; color: #34495e; }
code { background: #eef2f6; padding: 1px 4px; border-radius: 3px; font-size: 11px; }
ul { margin: 6px 0; padding-left: 20px; font-size: 12px; }
footer { text-align: center; font-size: 11px; color: #7f8c8d; padding: 16px; }
"""


def esc(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _fmt(value: Any) -> str:
    if value is None or value == "":
        return "&mdash;"
    return esc(value)


def _meta_row(label: str, value: Any) -> str:
    return f"<tr><th>{esc(label)}</th><td>{_fmt(value)}</td></tr>"


def _render_summary(report: IncidentReport) -> str:
    return (
        "<section class='summary'><h2>Summary</h2>"
        f"<p>{_fmt(report.report_summary)}</p>"
        "</section>"
    )


def _render_evidence(report: IncidentReport) -> str:
    ev = report.observed_evidence
    inc = ev.incident

    incident_rows = "".join(
        [
            _meta_row("Incident ID", inc.incident_id),
            _meta_row("Title", inc.title),
            _meta_row("Status", inc.status),
            _meta_row("Severity", inc.severity),
            _meta_row("First seen", inc.first_seen),
            _meta_row("Last seen", inc.last_seen),
            _meta_row("Duration (s)", inc.duration_seconds),
            _meta_row("Correlated alerts", inc.alert_count),
            _meta_row("Correlation score", inc.correlation_score),
        ]
    )

    entity_rows = "".join(
        [
            _meta_row("Affected users", ", ".join(ev.affected_users) or None),
            _meta_row("Affected hosts", ", ".join(ev.affected_hosts) or None),
            _meta_row("Source IPs", ", ".join(ev.source_ips) or None),
            _meta_row("Destination IPs", ", ".join(ev.destination_ips) or None),
            _meta_row("Detection methods", ", ".join(ev.detection_methods) or None),
            _meta_row("Correlation reasons", "; ".join(inc.correlation_reasons) or None),
        ]
    )

    alert_rows = "".join(
        f"<tr>"
        f"<td><code>{_fmt(a.evidence_ids and ' '.join(a.evidence_ids))}</code></td>"
        f"<td>{_fmt(a.timestamp)}</td>"
        f"<td>{_fmt(a.event_type)}</td>"
        f"<td>{_fmt(a.rule_name)}</td>"
        f"<td>{_fmt(a.severity)}</td>"
        f"<td>{_fmt(a.detection_method)}</td>"
        f"<td>{_fmt(a.source_ip)}</td>"
        f"<td>{_fmt(a.user)}</td>"
        f"<td>{_fmt(a.host)}</td>"
        f"<td>{_fmt(a.potential_attack_stage)}</td>"
        f"</tr>"
        for a in ev.correlated_alerts
    )

    timeline_rows = "".join(
        f"<tr>"
        f"<td>{_fmt(e.timestamp)}</td>"
        f"<td>{_fmt(e.event_type)}</td>"
        f"<td>{_fmt(e.source_ip)}</td>"
        f"<td>{_fmt(e.user)}</td>"
        f"<td>{_fmt(e.host)}</td>"
        f"<td>{_fmt(e.severity)}</td>"
        f"<td>{_fmt(e.stage)}</td>"
        f"<td>{_fmt(e.description)}</td>"
        f"</tr>"
        for e in ev.attack_timeline.entries
    )

    return (
        "<section class='evidence'><h2>1. Observed Evidence</h2>"
        "<p class='notice'>Facts recorded by Nexus One from correlated alerts and events.</p>"
        f"<h3>Incident</h3><table>{incident_rows}</table>"
        f"<h3>Observed entities</h3><table>{entity_rows}</table>"
        "<h3>Correlated alerts</h3>"
        "<table><tr><th>Evidence IDs</th><th>Timestamp</th><th>Event type</th>"
        "<th>Rule</th><th>Severity</th><th>Detection</th><th>Source IP</th>"
        "<th>User</th><th>Host</th><th>Potential stage</th></tr>"
        f"{alert_rows}</table>"
        "<h3>Attack timeline</h3>"
        "<table><tr><th>Timestamp</th><th>Event type</th><th>Source IP</th>"
        "<th>User</th><th>Host</th><th>Severity</th><th>Stage</th><th>Description</th></tr>"
        f"{timeline_rows}</table>"
        "</section>"
    )


def _render_analysis(report: IncidentReport) -> str:
    an = report.analysis
    parts: List[str] = []
    parts.append(
        "<section class='analysis'><h2>2. Analysis (Advisory)</h2>"
        f"<p class='notice'>{esc(an.analysis_notice)}</p>"
    )

    risk = an.deterministic_risk_assessment
    if risk:
        risk_rows = "".join(
            [
                _meta_row("Risk score", risk.get("risk_score")),
                _meta_row("Risk level", risk.get("risk_level")),
                _meta_row("Contributing factors", "; ".join(risk.get("contributing_factors") or []) or None),
                _meta_row("Scoring explanation", risk.get("scoring_explanation")),
            ]
        )
        parts.append(f"<h3>Deterministic risk assessment</h3><table>{risk_rows}</table>")

    if an.potential_attack_stages:
        stage_items = "".join(f"<li>{esc(s)}</li>" for s in an.potential_attack_stages)
        parts.append(f"<h3>Potential attack stages</h3><ul>{stage_items}</ul>")

    if an.ai_investigation is not None:
        inv = an.ai_investigation
        meta = an.investigation_metadata
        meta_line = ""
        if meta is not None:
            meta_line = (
                f" <small>(provider: {esc(meta.provider)}; mode: {esc(meta.analysis_mode)}; "
                f"generated: {esc(meta.generated_at)}; confidence: {_fmt(meta.confidence)})</small>"
            )
        parts.append(f"<h3>AI investigation{meta_line}</h3>")
        parts.append(f"<div class='rec-field'><span class='label'>Summary:</span> {_fmt(inv.incident_summary)}</div>")
        parts.append(f"<div class='rec-field'><span class='label'>Threat assessment:</span> {_fmt(inv.threat_assessment)}</div>")
        parts.append(f"<div class='rec-field'><span class='label'>Attack narrative:</span> {_fmt(inv.attack_narrative)}</div>")
        if inv.investigation_findings:
            finding_items = "".join(
                f"<li><b>{esc(f.title)}</b> &mdash; {esc(f.detail)} "
                f"<small>[{esc(', '.join(f.evidence_ids))}]</small></li>"
                for f in inv.investigation_findings
            )
            parts.append(f"<div class='rec-field'><span class='label'>Findings:</span></div><ul>{finding_items}</ul>")
        if inv.recommended_next_steps:
            step_items = "".join(f"<li>{esc(s)}</li>" for s in inv.recommended_next_steps)
            parts.append(f"<div class='rec-field'><span class='label'>AI-suggested next steps (advisory):</span></div><ul>{step_items}</ul>")
    else:
        parts.append(
            "<h3>AI investigation</h3>"
            "<p>No AI investigation has been run for this incident. "
            "Run <code>POST /incidents/{id}/investigate</code> to add one.</p>"
        )

    if an.uncertainties:
        uncertainty_items = "".join(f"<li>{esc(u)}</li>" for u in an.uncertainties)
        parts.append(f"<h3>Uncertainties</h3><ul>{uncertainty_items}</ul>")

    parts.append("</section>")
    return "".join(parts)


def _render_actions(report: IncidentReport) -> str:
    ra = report.recommended_actions
    parts: List[str] = []
    parts.append(
        "<section class='actions'><h2>3. Recommended Actions (Advisory)</h2>"
        f"<p class='notice actions'>{esc(ra.advisory_notice)} "
        "No action has been executed; every recommendation requires explicit analyst "
        "approval.</p>"
    )

    for rec in ra.recommendations:
        factors = "; ".join(rec.priority_factors) or None
        parts.append(
            "<div class='rec'>"
            f"<div class='rec-title'>{esc(rec.title)}</div>"
            f"<div class='rec-meta'>"
            f"<span class='badge {esc(rec.priority)}'>{esc(rec.priority)}</span> "
            f"&middot; {esc(rec.category)} &middot; priority score {_fmt(rec.priority_score)}/100 "
            f"&middot; confidence {_fmt(rec.confidence)} &middot; "
            f"<b>requires analyst approval</b>"
            "</div>"
            f"<div class='rec-field'>{esc(rec.description)}</div>"
            f"<div class='rec-field'><span class='label'>Rationale:</span> {esc(rec.rationale)}</div>"
            f"<div class='rec-field'><span class='label'>Priority factors:</span> {_fmt(factors)}</div>"
            f"<div class='rec-field'><span class='label'>Evidence:</span> "
            f"<code>{esc(' '.join(rec.evidence_ids)) or '&mdash;'}</code></div>"
            "</div>"
        )

    if not ra.recommendations:
        parts.append("<p>No recommendations were generated for this incident.</p>")

    parts.append("</section>")
    return "".join(parts)


def render_report_html(report: IncidentReport) -> str:
    """Render a validated IncidentReport model as a complete HTML document."""
    header = (
        "<header class='report'>"
        f"<h1>{esc(report.title)}</h1>"
        "<div class='meta'>"
        f"Report <code>{esc(report.report_id)}</code> &middot; "
        f"incident <code>{esc(report.incident_id)}</code> &middot; "
        f"generated {esc(report.generated_at)} &middot; "
        f"format {esc(report.format_version)}"
        "</div>"
        "</header>"
    )

    legend = (
        "<section class='summary'>"
        "<h2>How to read this report</h2>"
        "<ul>"
        "<li><b>1. Observed Evidence</b> &mdash; facts recorded by Nexus One.</li>"
        "<li><b>2. Analysis</b> &mdash; deterministic scoring plus advisory AI narrative; "
        "not confirmed fact.</li>"
        "<li><b>3. Recommended Actions</b> &mdash; advisory only; require analyst approval; "
        "never executed automatically.</li>"
        "</ul>"
        "</section>"
    )

    return (
        "<!DOCTYPE html>"
        "<html lang='en'><head><meta charset='utf-8'>"
        f"<title>{esc(report.title)}</title>"
        f"<style>{_STYLE}</style></head>"
        "<body><div class='container'>"
        f"{header}"
        f"{legend}"
        f"{_render_summary(report)}"
        f"{_render_evidence(report)}"
        f"{_render_analysis(report)}"
        f"{_render_actions(report)}"
        "<footer>Generated by Nexus One &mdash; advisory output for SOC analysts; "
        "no automated response actions were executed.</footer>"
        "</div></body></html>"
    )
