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


def build_demo_report(context: Dict[str, Any]) -> Dict[str, Any]:
    incident = context.get("incident", {})
    alerts: List[Dict[str, Any]] = context.get("alerts", [])
    risk = context.get("deterministic_risk_assessment") or {}
    stages: List[str] = context.get("potential_attack_stages", [])
    entities = context.get("observed_entities", {})
    notes = context.get("context_notes", {}) or {}

    risk_level = _fmt(risk.get("risk_level"), "not scored")
    risk_score = risk.get("risk_score")

    # --- incident_summary -------------------------------------------------
    summary = (
        f"Incident '{_fmt(incident.get('title'))}' (severity "
        f"{_fmt(incident.get('severity'))}, status {_fmt(incident.get('status'))}) "
        f"contains {len(alerts)} correlated alert(s) observed between "
        f"{_fmt(incident.get('first_seen'))} and {_fmt(incident.get('last_seen'))}."
    )
    if risk_score is not None:
        summary += (
            f" The deterministic risk engine rated it {risk_level} "
            f"({risk_score}/100)."
        )

    # --- threat_assessment ------------------------------------------------
    assessment = ""
    if risk_score is not None:
        assessment += (
            f"The deterministic risk engine assessed this incident as {risk_level} "
            f"({risk_score}/100)."
        )
        factors = risk.get("contributing_factors") or []
        if factors:
            assessment += " Contributing factors: " + "; ".join(factors) + "."
    else:
        assessment += "No deterministic risk assessment was supplied. "
    if stages:
        assessment += (
            " Based solely on the observed alerts, the activity is consistent with "
            f"the following attack stages: {', '.join(stages)}. This is an "
            "evidence-based assessment, not a confirmed attack."
        )
    else:
        assessment += (
            " The supplied evidence does not clearly map to a known attack "
            "pattern."
        )

    # --- evidence ----------------------------------------------------------
    evidence = []
    for a in alerts:
        ids = [i for i in (a.get("id"), a.get("event_id")) if i]
        label = a.get("rule_name") or a.get("event_type") or "alert"
        evidence.append(
            {
                "description": (
                    f"[{a.get('severity', 'info')}] {label}: "
                    f"{_fmt(a.get('detection_reason'), 'no detection reason supplied')}"
                ),
                "evidence_ids": ids,
            }
        )

    # --- attack_narrative ---------------------------------------------------
    narrative_parts = []
    for a in alerts:
        ts = _fmt(a.get("timestamp"), "an unknown time")
        label = a.get("rule_name") or a.get("event_type") or "an alert"
        detail = _fmt(a.get("detection_reason"), f"alert from rule '{label}'")
        sentence = f"At {ts}, {label} fired: {detail}"
        actor_bits = []
        if a.get("user"):
            actor_bits.append(f"user {a['user']}")
        if a.get("host"):
            actor_bits.append(f"host {a['host']}")
        if a.get("source_ip"):
            actor_bits.append(f"source IP {a['source_ip']}")
        if a.get("destination_ip"):
            actor_bits.append(f"destination IP {a['destination_ip']}")
        if actor_bits:
            sentence += f" ({', '.join(actor_bits)})"
        if not sentence.endswith("."):
            sentence += "."
        narrative_parts.append(sentence)

    if narrative_parts:
        attack_narrative = " ".join(narrative_parts)
    else:
        attack_narrative = "No alert evidence was supplied for this incident."

    # --- affected_entities ----------------------------------------------------
    affected: List[str] = []
    affected += [f"host: {h}" for h in entities.get("hosts", [])]
    affected += [f"user: {u}" for u in entities.get("users", [])]
    affected += [f"source_ip: {ip}" for ip in entities.get("source_ips", [])]
    affected += [f"destination_ip: {ip}" for ip in entities.get("destination_ips", [])]

    # --- investigation_findings -----------------------------------------------
    findings = []
    if alerts:
        all_alert_ids = [a["id"] for a in alerts if a.get("id")]
        reasons = incident.get("correlation_reasons") or []
        findings.append(
            {
                "title": "Alerts correlated into a single incident",
                "detail": (
                    f"{len(alerts)} alert(s) were correlated into this incident "
                    f"(correlation score {_fmt(incident.get('correlation_score'))})"
                    + (". Reasons: " + "; ".join(reasons) if reasons else "")
                ),
                "evidence_ids": all_alert_ids,
            }
        )
        for a in alerts[:10]:
            ids = [i for i in (a.get("id"), a.get("event_id")) if i]
            label = a.get("rule_name") or a.get("event_type") or "Alert"
            detail = _fmt(a.get("detection_reason"), "No detection reason supplied.")
            ml = a.get("ml_anomaly")
            if ml:
                detail += f" ML anomaly context: score {ml.get('anomaly_score')}."
            findings.append(
                {"title": str(label), "detail": detail, "evidence_ids": ids}
            )

    # --- uncertainties -----------------------------------------------------
    uncertainties = [
        "This report was generated by the deterministic DEMO/MOCK provider, "
        "not a live language model."
    ]
    if not alerts:
        uncertainties.append(
            "No alert evidence was available; no conclusions can be drawn."
        )
    else:
        if not any(a.get("ml_anomaly") or a.get("detection_method") == "ml" for a in alerts):
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
                "evidence does not prove attacker intent."
            )
    if notes.get("alerts_truncated"):
        uncertainties.append(
            "The evidence was truncated to the earliest alerts; later alerts in "
            "this incident were not analysed."
        )

    # --- recommended_next_steps ----------------------------------------------
    next_steps = []
    for host in entities.get("hosts", [])[:3]:
        next_steps.append(
            f"Review recent activity on host '{host}' for the observed alert pattern."
        )
    for user in entities.get("users", [])[:3]:
        next_steps.append(
            f"With analyst approval, verify whether the account '{user}' shows "
            "unauthorised activity and reset its credentials if compromised."
        )
    for ip in entities.get("source_ips", [])[:3]:
        next_steps.append(
            f"Check whether source IP {ip} appears in threat intelligence feeds "
            "and other logs across the environment."
        )
    next_steps.append(
        "Correlate this incident with external telemetry (firewall, EDR, "
        "authentication logs) to confirm or refute the assessment."
    )
    if stages:
        next_steps.append(
            "Map the observed stages against the kill chain to identify detection "
            "gaps and missing evidence."
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
