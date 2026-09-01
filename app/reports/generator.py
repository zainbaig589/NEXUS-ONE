"""Assembles structured incident reports from already-computed artifacts.

Pure function over its inputs: the incident model, its alerts/events, the
deterministic risk and timeline outputs, the persisted AI investigation
record, and the recommendation payload from ``app.response``.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.attack_stages import get_distinct_stages
from app.reports.schemas import (
    ANALYSIS_NOTICE,
    REPORT_FORMAT_VERSION,
    IncidentReport,
    ReportAlertSummary,
    ReportAnalysis,
    ReportIncidentInfo,
    ReportInvestigationMetadata,
    ReportObservedEvidence,
    ReportRecommendedActions,
    ReportTimeline,
    ReportTimelineEntry,
)
from app.response.engine import build_alert_views


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if value is not None else None


def _potential_stages(incident: Any, alerts: List[Any]) -> List[str]:
    stored = list(getattr(incident, "attack_stages", None) or [])
    if stored:
        return stored
    return [f"Potential stage: {s}" for s in get_distinct_stages(alerts)]


def _summary_sentence(
    incident: Any,
    risk: Optional[Dict[str, Any]],
    alert_count: int,
    stages: List[str],
    recommendation_count: int,
) -> str:
    severity = getattr(incident, "severity", None) or "unknown"
    risk_level = (risk or {}).get("risk_level") or getattr(incident, "risk_level", None) or "LOW"
    risk_score = (risk or {}).get("risk_score", getattr(incident, "risk_score", None))
    risk_part = f"{risk_level} risk" + (f" ({risk_score:.1f}/100)" if risk_score is not None else "")
    stage_part = (
        f" Evidence spans {len(stages)} potential kill-chain stage(s)."
        if stages
        else ""
    )
    recommendation_part = (
        f" {recommendation_count} advisory response recommendation(s) were generated; "
        "all require analyst approval and none are executed automatically."
        if recommendation_count
        else " No response recommendations were generated."
    )
    return (
        f"Incident '{getattr(incident, 'title', None) or getattr(incident, 'id', '')}' "
        f"({severity} severity, {risk_part}) correlates {alert_count} alert(s)."
        f"{stage_part}{recommendation_part}"
    )


def build_incident_report(
    incident: Any,
    alerts: List[Any],
    events_by_alert: Optional[Dict[str, Any]],
    risk: Optional[Dict[str, Any]],
    timeline: Optional[Dict[str, Any]],
    investigation: Optional[Dict[str, Any]],
    recommendations_result: Dict[str, Any],
) -> IncidentReport:
    """Build the full structured report for one incident."""
    now = datetime.now(timezone.utc)
    timeline = timeline or {}

    views = build_alert_views(alerts, events_by_alert)
    events = {}
    for alert in alerts:
        event = (
            events_by_alert.get(getattr(alert, "id", None))
            if events_by_alert
            else getattr(alert, "event", None)
        )
        events[getattr(alert, "id", None)] = event

    alert_summaries = [
        ReportAlertSummary(
            alert_id=view.alert_id,
            event_id=view.event_id,
            evidence_ids=view.evidence_ids,
            timestamp=_iso(getattr(events.get(view.alert_id), "timestamp", None)),
            event_type=view.event_type,
            rule_name=view.rule_name,
            severity=view.severity,
            detection_method=view.detection_method,
            description=view.description,
            source_ip=view.source_ip,
            destination_ip=view.destination_ip,
            user=view.user,
            host=view.host,
            potential_attack_stage=f"Potential stage: {view.stage}" if view.stage else None,
        )
        for view in views
    ]

    timeline_entries = [
        ReportTimelineEntry(
            timestamp=_iso(entry.get("timestamp")),
            event_id=entry.get("event_id"),
            alert_id=entry.get("alert_id"),
            event_type=entry.get("event_type"),
            source_ip=entry.get("source_ip"),
            destination_ip=entry.get("destination_ip"),
            user=entry.get("user"),
            host=entry.get("host"),
            severity=entry.get("severity"),
            detection_method=entry.get("detection_method"),
            description=entry.get("description"),
            stage=entry.get("stage"),
        )
        for entry in timeline.get("entries", [])
    ]

    stages = _potential_stages(incident, alerts)

    ai_report = None
    investigation_metadata = None
    uncertainties: List[str] = []
    if investigation:
        raw_report = investigation.get("investigation") or {}
        if raw_report:
            ai_report = raw_report
        investigation_metadata = ReportInvestigationMetadata(
            provider=investigation.get("provider") or "unknown",
            analysis_mode=investigation.get("analysis_mode") or "unknown",
            generated_at=investigation.get("generated_at") or "",
            confidence=(raw_report or {}).get("confidence"),
        )
        uncertainties = list((raw_report or {}).get("uncertainties") or [])
        investigation_status = "available"
    else:
        investigation_status = "not_run"
        uncertainties = [
            "No AI investigation has been run for this incident yet; analysis in this "
            "report relies on deterministic scoring only."
        ]

    recommendations = list(recommendations_result.get("recommendations") or [])

    observed = ReportObservedEvidence(
        incident=ReportIncidentInfo(
            incident_id=getattr(incident, "id", None),
            title=getattr(incident, "title", None),
            status=getattr(incident, "status", None),
            severity=getattr(incident, "severity", None),
            description=getattr(incident, "description", None),
            first_seen=_iso(getattr(incident, "first_seen", None)),
            last_seen=_iso(getattr(incident, "last_seen", None)),
            duration_seconds=timeline.get("duration_seconds", 0) or 0,
            alert_count=getattr(incident, "alert_count", len(alerts)) or 0,
            correlation_score=getattr(incident, "correlation_score", None),
            correlation_reasons=list(getattr(incident, "correlation_reasons", None) or []),
        ),
        affected_users=list(getattr(incident, "users", None) or []),
        affected_hosts=list(getattr(incident, "hosts", None) or []),
        source_ips=list(getattr(incident, "source_ips", None) or []),
        destination_ips=list(getattr(incident, "destination_ips", None) or []),
        correlated_alerts=alert_summaries,
        detection_methods=sorted(
            {v.detection_method for v in views if v.detection_method}
        ),
        attack_timeline=ReportTimeline(
            first_seen=_iso(timeline.get("first_seen")),
            last_seen=_iso(timeline.get("last_seen")),
            duration_seconds=timeline.get("duration_seconds", 0) or 0,
            entries=timeline_entries,
        ),
    )

    analysis = ReportAnalysis(
        analysis_notice=ANALYSIS_NOTICE,
        deterministic_risk_assessment=(
            {
                "risk_score": risk.get("risk_score"),
                "risk_level": risk.get("risk_level"),
                "contributing_factors": list(risk.get("contributing_factors", []) or []),
                "scoring_explanation": risk.get("scoring_explanation"),
            }
            if risk
            else None
        ),
        potential_attack_stages=stages,
        ai_investigation=ai_report,
        investigation_metadata=investigation_metadata,
        investigation_status=investigation_status,
        uncertainties=uncertainties,
    )

    actions = ReportRecommendedActions(
        advisory_notice=recommendations_result.get("advisory_notice") or "",
        all_actions_require_analyst_approval=True,
        recommendations=recommendations,
    )

    return IncidentReport(
        report_id=f"rpt-{uuid.uuid4().hex[:12]}",
        incident_id=getattr(incident, "id", None),
        generated_at=now.isoformat(),
        format_version=REPORT_FORMAT_VERSION,
        title=f"Incident Report: {getattr(incident, 'title', None) or getattr(incident, 'id', '')}",
        report_summary=_summary_sentence(
            incident,
            risk,
            alert_count=getattr(incident, "alert_count", len(alerts)) or 0,
            stages=stages,
            recommendation_count=len(recommendations),
        ),
        evidence_references=sorted({eid for v in views for eid in v.evidence_ids}),
        observed_evidence=observed,
        analysis=analysis,
        recommended_actions=actions,
    )
