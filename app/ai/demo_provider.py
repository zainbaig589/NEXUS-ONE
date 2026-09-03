"""Deterministic DEMO/MOCK investigation provider.

Generates a realistic structured investigation report purely from the
supplied evidence payload — it never invents events, IPs, users, hosts, or
timestamps, and it cites only the evidence IDs present in the payload.
Used for local development, demos, and CI where no LLM is available.
"""

import json
from typing import Any, Dict, List

from app.ai.providers import LLMProvider


def _fmt(value: Any, fallback: str = "unknown") -> str:
    return value if value not in (None, "") else fallback


class DemoInvestigatorProvider(LLMProvider):
    name = "demo"

    def investigate(self, context: Dict[str, Any]) -> str:
        report = build_demo_report(context)
        return json.dumps(report, indent=2, ensure_ascii=False)


def _severity_rank(sev: str | None) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get((sev or "").lower(), 0)


def _format_ts(ts: Any) -> str:
    if ts is None or ts == "":
        return "an unknown time"
    return str(ts)


def _evidence_label(alert: Dict[str, Any]) -> str:
    return alert.get("rule_name") or alert.get("event_type") or "alert"


def build_demo_report(context: Dict[str, Any]) -> Dict[str, Any]:
    incident = context.get("incident", {})
    alerts: List[Dict[str, Any]] = context.get("alerts", [])
    risk = context.get("deterministic_risk_assessment") or {}
    stages: List[str] = context.get("potential_attack_stages", [])
    entities = context.get("observed_entities", {})
    notes = context.get("context_notes", {}) or {}
    timeline_ctx = context.get("timeline", {}) or {}

    risk_level = _fmt(risk.get("risk_level"), "not scored")
    risk_score = risk.get("risk_score")

    sorted_alerts = sorted(alerts, key=lambda a: str(a.get("timestamp") or ""))
    severity_counts: Dict[str, int] = {}
    for a in alerts:
        sev = (a.get("severity") or "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    hosts = entities.get("hosts", [])
    users = entities.get("users", [])
    source_ips = entities.get("source_ips", [])
    dest_ips = entities.get("destination_ips", [])

    # --- incident_summary -------------------------------------------------
    title = _fmt(incident.get("title"))
    severity = _fmt(incident.get("severity"))
    status = _fmt(incident.get("status"))
    first_seen = _fmt(incident.get("first_seen"), "unknown")
    last_seen = _fmt(incident.get("last_seen"), "unknown")
    alert_count = len(alerts)

    summary_parts = [
        f"Security incident '{title}' has been identified with {severity} severity "
        f"and is currently in '{status}' status."
    ]
    if alert_count > 0:
        sev_breakdown = ", ".join(
            f"{count} {sev.upper()}" for sev, count in sorted(severity_counts.items())
        )
        summary_parts.append(
            f"The incident comprises {alert_count} correlated alert(s) "
            f"({sev_breakdown}) observed between {first_seen} and {last_seen}."
        )
    if risk_score is not None:
        summary_parts.append(
            f"The deterministic risk engine assigned a risk score of "
            f"{risk_score}/100 ({risk_level}), indicating "
            f"{'significant' if risk_score >= 60 else 'moderate' if risk_score >= 35 else 'low'} "
            f"potential impact to the environment."
        )
    if hosts:
        summary_parts.append(
            f"Affected assets include {len(hosts)} host(s): {', '.join(hosts[:3])}"
            + (f" and {len(hosts) - 3} more" if len(hosts) > 3 else "")
            + "."
        )
    if users:
        summary_parts.append(
            f"User account(s) involved: {', '.join(users[:3])}."
        )
    if stages:
        summary_parts.append(
            f"Alert patterns are consistent with {len(stages)} attack stage(s): "
            f"{', '.join(stages)}."
        )
    summary = " ".join(summary_parts)

    # --- threat_assessment ------------------------------------------------
    assessment_parts = []
    if risk_score is not None:
        assessment_parts.append(
            f"RISK ASSESSMENT: The deterministic risk engine scored this incident "
            f"{risk_score}/100 ({risk_level})."
        )
        scoring_explanation = risk.get("scoring_explanation")
        if scoring_explanation:
            assessment_parts.append(str(scoring_explanation))
        factors = risk.get("contributing_factors") or []
        if factors:
            assessment_parts.append(
                f"Contributing factors ({len(factors)}): "
                + "; ".join(factors) + "."
            )
    else:
        assessment_parts.append(
            "No deterministic risk assessment was supplied for this incident."
        )

    if stages:
        assessment_parts.append(
            f"ATTACK PATTERN ANALYSIS: The observed alert sequence maps to "
            f"{len(stages)} potential attack stage(s): {', '.join(stages)}. "
            f"This progression {'suggests a coordinated, multi-stage attack' if len(stages) >= 3 else 'indicates targeted activity'} "
            f"rather than isolated security events."
        )
    else:
        assessment_parts.append(
            "The supplied evidence does not clearly map to a known multi-stage "
            "attack pattern."
        )

    if source_ips:
        assessment_parts.append(
            f"SOURCE ANALYSIS: {len(source_ips)} unique source IP(s) observed: "
            f"{', '.join(source_ips[:5])}. "
            "These should be checked against threat intelligence feeds."
        )
    if users:
        assessment_parts.append(
            f"ACCOUNT ANALYSIS: {len(users)} user account(s) involved in the "
            f"alert sequence. Credential compromise should be investigated."
        )

    ml_alerts = [a for a in alerts if a.get("ml_anomaly") or a.get("detection_method") == "ml"]
    if ml_alerts:
        assessment_parts.append(
            f"ML DETECTION: {len(ml_alerts)} alert(s) were flagged by the ML "
            f"anomaly detector, providing additional behavioural context beyond "
            f"rule-based detection."
        )

    assessment_parts.append(
        "This assessment is based solely on the supplied evidence and does not "
        "constitute a confirmed attack determination."
    )
    assessment = " ".join(assessment_parts)

    # --- evidence ----------------------------------------------------------
    evidence = []
    for a in sorted_alerts:
        ids = [i for i in (a.get("id"), a.get("event_id")) if i]
        label = _evidence_label(a)
        sev = a.get("severity", "info")
        method = a.get("detection_method", "rule")
        evidence.append(
            {
                "description": (
                    f"[{sev.upper()}] {label} (detected via {method}): "
                    f"{_fmt(a.get('detection_reason'), 'no detection reason supplied')}"
                ),
                "evidence_ids": ids,
            }
        )

    # --- attack_narrative ---------------------------------------------------
    narrative_parts = []
    if sorted_alerts:
        narrative_parts.append(
            f"The following chronological sequence reconstructs the observed "
            f"activity across {alert_count} alert(s):"
        )

    for idx, a in enumerate(sorted_alerts, 1):
        ts = _format_ts(a.get("timestamp"))
        label = _evidence_label(a)
        detail = _fmt(a.get("detection_reason"), f"alert from rule '{label}'")
        citation_ids = [i for i in (a.get("id"), a.get("event_id")) if i]
        citation_str = f" [{', '.join(citation_ids)}]" if citation_ids else ""

        sentence = f"({idx}) At {ts}, {label} fired{citation_str}: {detail}"

        actor_bits = []
        if a.get("source_ip"):
            actor_bits.append(f"from {a['source_ip']}")
        if a.get("destination_ip"):
            actor_bits.append(f"targeting {a['destination_ip']}")
        if a.get("user"):
            actor_bits.append(f"involving user '{a['user']}'")
        if a.get("host"):
            actor_bits.append(f"on host '{a['host']}'")
        if actor_bits:
            sentence += " " + " ".join(actor_bits)

        stage = a.get("potential_attack_stage")
        if stage:
            sentence += f" [stage: {stage}]"

        ml = a.get("ml_anomaly")
        if ml:
            sentence += (
                f" (ML anomaly score: {ml.get('anomaly_score', 'N/A')})"
            )

        if not sentence.endswith("."):
            sentence += "."
        narrative_parts.append(sentence)

    if stages and len(sorted_alerts) > 1:
        narrative_parts.append(
            f"The observed progression through {', '.join(stages)} "
            f"{'indicates a sophisticated, multi-phase operation' if len(stages) >= 3 else 'suggests escalating attacker activity'}."
        )

    if narrative_parts:
        attack_narrative = " ".join(narrative_parts)
    else:
        attack_narrative = "No alert evidence was supplied for this incident."

    # --- affected_entities ----------------------------------------------------
    affected: List[str] = []
    affected += [f"host: {h}" for h in hosts]
    affected += [f"user: {u}" for u in users]
    affected += [f"source_ip: {ip}" for ip in source_ips]
    affected += [f"destination_ip: {ip}" for ip in dest_ips]

    # --- investigation_findings -----------------------------------------------
    findings = []
    finding_num = 0

    if alerts:
        finding_num += 1
        all_alert_ids = [a["id"] for a in alerts if a.get("id")]
        corr_score = _fmt(incident.get("correlation_score"))
        reasons = incident.get("correlation_reasons") or []
        reasons_str = f" Correlation reasons: {'; '.join(reasons)}." if reasons else ""
        findings.append(
            {
                "title": "Multi-alert correlation into single incident",
                "detail": (
                    f"{len(alerts)} alert(s) were correlated into this incident "
                    f"with a correlation score of {corr_score}.{reasons_str} "
                    f"This indicates the alerts share common indicators "
                    f"(IPs, users, hosts) within the correlation time window."
                ),
                "evidence_ids": all_alert_ids,
            }
        )

    if stages:
        finding_num += 1
        stage_alert_map: Dict[str, List[str]] = {}
        for a in sorted_alerts:
            stage = a.get("potential_attack_stage")
            if stage:
                ids = [i for i in (a.get("id"), a.get("event_id")) if i]
                stage_alert_map.setdefault(stage, []).extend(ids)
        stage_evidence_ids = []
        for ids in stage_alert_map.values():
            stage_evidence_ids.extend(ids)
        findings.append(
            {
                "title": f"Attack chain progression detected ({len(stages)} stages)",
                "detail": (
                    f"The alert sequence maps to {len(stages)} distinct attack "
                    f"stages: {', '.join(stages)}. "
                    f"This multi-stage pattern suggests coordinated attacker "
                    f"activity progressing through the kill chain."
                ),
                "evidence_ids": stage_evidence_ids if stage_evidence_ids else all_alert_ids if alerts else [],
            }
        )

    if source_ips:
        finding_num += 1
        ip_evidence = []
        for a in alerts:
            if a.get("source_ip") in source_ips:
                ip_evidence.extend([i for i in (a.get("id"), a.get("event_id")) if i])
        findings.append(
            {
                "title": f"External source IP activity ({len(source_ips)} unique IP(s))",
                "detail": (
                    f"Source IP(s) {', '.join(source_ips[:5])} "
                    f"{'were' if len(source_ips) == 1 else 'were'} observed "
                    f"across {len(ip_evidence)} evidence item(s). "
                    f"These IPs should be checked against threat intelligence "
                    f"feeds and geo-IP databases."
                ),
                "evidence_ids": list(set(ip_evidence)),
            }
        )

    if users:
        finding_num += 1
        user_evidence = []
        for a in alerts:
            if a.get("user") in users:
                user_evidence.extend([i for i in (a.get("id"), a.get("event_id")) if i])
        findings.append(
            {
                "title": f"User account involvement ({len(users)} account(s))",
                "detail": (
                    f"User account(s) {', '.join(users[:5])} "
                    f"{'was' if len(users) == 1 else 'were'} involved in "
                    f"{len(user_evidence)} evidence item(s). "
                    f"Credential compromise should be investigated, "
                    f"especially if privilege escalation stages are present."
                ),
                "evidence_ids": list(set(user_evidence)),
            }
        )

    if hosts:
        finding_num += 1
        host_evidence = []
        for a in alerts:
            if a.get("host") in hosts:
                host_evidence.extend([i for i in (a.get("id"), a.get("event_id")) if i])
        findings.append(
            {
                "title": f"Affected host systems ({len(hosts)} host(s))",
                "detail": (
                    f"Host(s) {', '.join(hosts[:5])} "
                    f"{'was' if len(hosts) == 1 else 'were'} involved in "
                    f"{len(host_evidence)} evidence item(s). "
                    f"System-level investigation should check for persistence "
                    f"mechanisms, lateral movement, and data access."
                ),
                "evidence_ids": list(set(host_evidence)),
            }
        )

    ml_alerts = [a for a in alerts if a.get("ml_anomaly")]
    if ml_alerts:
        finding_num += 1
        ml_evidence = []
        for a in ml_alerts:
            ml_evidence.extend([i for i in (a.get("id"), a.get("event_id")) if i])
        findings.append(
            {
                "title": f"ML anomaly detection correlation ({len(ml_alerts)} alert(s))",
                "detail": (
                    f"{len(ml_alerts)} alert(s) were also flagged by the ML "
                    f"anomaly detector, providing behavioural context beyond "
                    f"rule-based detection. "
                    f"Anomaly scores ranged from "
                    f"{min(a['ml_anomaly'].get('anomaly_score', 0) for a in ml_alerts if a.get('ml_anomaly'))} "
                    f"to "
                    f"{max(a['ml_anomaly'].get('anomaly_score', 0) for a in ml_alerts if a.get('ml_anomaly'))}."
                ),
                "evidence_ids": list(set(ml_evidence)),
            }
        )

    for a in sorted_alerts[:8]:
        finding_num += 1
        ids = [i for i in (a.get("id"), a.get("event_id")) if i]
        label = _evidence_label(a)
        sev = a.get("severity", "info")
        detail = _fmt(a.get("detection_reason"), "No detection reason supplied.")
        stage = a.get("potential_attack_stage")
        if stage:
            detail = f"Attack stage: {stage}. {detail}"
        ml = a.get("ml_anomaly")
        if ml:
            detail += f" ML anomaly score: {ml.get('anomaly_score')}."
        findings.append(
            {
                "title": f"[{sev.upper()}] {label}",
                "detail": detail,
                "evidence_ids": ids,
            }
        )

    # --- uncertainties -----------------------------------------------------
    uncertainties = [
        "This report was generated by the deterministic DEMO/MOCK provider, "
        "not a live language model. Conclusions are evidence-based but limited "
        "to the supplied context."
    ]
    if not alerts:
        uncertainties.append(
            "No alert evidence was available; no conclusions can be drawn."
        )
    else:
        if not ml_alerts:
            uncertainties.append(
                "No ML anomaly detections appear in the evidence; behavioural "
                "context for the involved accounts and hosts is unavailable."
            )
        uncertainties.append(
            "Correlation is based on shared indicators within the time window; "
            "coincidental indicator overlap cannot be ruled out."
        )
        if stages:
            uncertainties.append(
                "Attack stages are inferred from event types and rule names; the "
                "evidence does not prove attacker intent or confirm a real attack."
            )
        if not source_ips:
            uncertainties.append(
                "No source IP information was available in the evidence; "
                "network-level attribution is not possible."
            )
        if not users:
            uncertainties.append(
                "No user account information was available; account-level "
                "impact cannot be assessed."
            )
    if notes.get("alerts_truncated"):
        uncertainties.append(
            "The evidence was truncated to the earliest alerts; later alerts in "
            "this incident were not analysed."
        )

    # --- recommended_next_steps ----------------------------------------------
    next_steps = []

    if risk_score is not None and risk_score >= 60:
        next_steps.append(
            "IMMEDIATE: Escalate this incident to the senior security analyst "
            "or incident response lead given the high risk score."
        )

    for host in hosts[:3]:
        next_steps.append(
            f"Isolate and perform forensic analysis on host '{host}' — check "
            f"for persistence mechanisms, unauthorized processes, and data access."
        )
    for user in users[:3]:
        next_steps.append(
            f"Verify account '{user}' activity with the account owner. If "
            f"compromise is suspected, reset credentials and review all recent "
            f"authentication sessions."
        )
    for ip in source_ips[:3]:
        next_steps.append(
            f"Query threat intelligence feeds for source IP {ip} and check "
            f"whether it appears in other security events across the environment."
        )
    if stages:
        next_steps.append(
            "Map the observed attack stages against the MITRE ATT&CK framework "
            "to identify detection gaps and missing evidence."
        )
    next_steps.append(
        "Correlate this incident with external telemetry (firewall, EDR, "
        "DNS, authentication logs) to confirm or refute the assessment."
    )
    next_steps.append(
        "Document all findings, actions taken, and lessons learned in the "
        "incident tracking system for post-incident review."
    )

    # --- confidence -----------------------------------------------------------
    if not alerts:
        confidence = 0.2
    else:
        corr = incident.get("correlation_score") or 0.0
        confidence = round(
            min(0.4 + 0.06 * min(len(alerts), 5) + 0.2 * corr, 0.9), 2
        )

    return {
        "incident_summary": summary,
        "threat_assessment": assessment,
        "evidence": evidence,
        "attack_narrative": attack_narrative,
        "potential_attack_stages": stages,
        "affected_entities": affected,
        "investigation_findings": findings,
        "uncertainties": uncertainties,
        "recommended_next_steps": next_steps,
        "confidence": confidence,
    }
