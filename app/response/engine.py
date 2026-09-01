"""Deterministic response recommendation engine.

Given an incident and its correlated evidence, produces prioritised,
evidence-based response recommendations. The engine is fully
deterministic: the same evidence always yields the same recommendations,
priorities, and rationales. No LLM is involved in prioritisation — the
AI investigation record is an input signal only, never an authority on
response safety.

Every recommendation is advisory. Nexus One never executes response
actions; each recommendation requires explicit analyst approval.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from app.attack_stages import get_distinct_stages
from app.correlation.scorer import extract_indicators

# ---------------------------------------------------------------------------
# Configuration (centralised so priorities can be tuned without touching logic)
# ---------------------------------------------------------------------------

# Inclusive lower-bound thresholds for priority levels.
PRIORITY_LEVELS = [
    (80.0, "CRITICAL"),
    (60.0, "HIGH"),
    (35.0, "MEDIUM"),
    (0.0, "LOW"),
]

# Base score contributed by each rule before modifiers.
RULE_BASE_SCORES: Dict[str, float] = {
    "investigate-data-exfiltration": 70.0,
    "compromised-account": 65.0,
    "isolate-endpoint": 60.0,
    "review-privilege-changes": 55.0,
    "investigate-network-indicator": 50.0,
    "monitor-lateral-movement": 45.0,
    "review-authentication-activity": 40.0,
    "review-ai-investigation-findings": 35.0,
    "collect-additional-evidence": 30.0,
    "preserve-logs-for-forensics": 25.0,
}

# Deterministic modifiers applied on top of each rule's base score.
PRIORITY_WEIGHTS: Dict[str, Any] = {
    "risk_level_boost": {"CRITICAL": 30.0, "HIGH": 20.0, "MEDIUM": 10.0, "LOW": 0.0},
    "severity_boost": {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 2.0, "info": 0.0},
    "evidence_boost_per_alert": 2.0,
    "evidence_boost_max": 10.0,
    "multi_stage_boost": 5.0,
    "investigation_available_boost": 3.0,
}

# Confidence grows with the amount of supporting evidence.
CONFIDENCE_WEIGHTS: Dict[str, float] = {
    "base": 0.5,
    "per_matching_alert": 0.1,
    "max_matching_alerts": 3.0,
    "investigation_available": 0.05,
    "cap": 0.95,
}

ADVISORY_NOTICE = (
    "Nexus One provides advisory recommendations only. No response action is "
    "executed automatically by this system. Every recommendation requires "
    "explicit analyst approval before any action is taken."
)

# Event-type sets used by the rules (kept conservative and explicit).
CREDENTIAL_EVENT_TYPES = {"failed_login", "account_lockout", "authentication"}
PRIVILEGE_EVENT_TYPES = {"privilege_escalation"}
CONTAINMENT_EVENT_TYPES = {"privilege_escalation", "malware_detected", "lateral_movement"}
EXFILTRATION_EVENT_TYPES = {"data_transfer", "data_exfiltration"}
AUTH_EVENT_TYPES = {
    "failed_login",
    "account_lockout",
    "successful_login",
    "login",
    "logout",
    "authentication",
}
CONTAINMENT_STAGES = {"Privilege Escalation", "Execution", "Lateral Movement"}


# ---------------------------------------------------------------------------
# Evidence normalisation
# ---------------------------------------------------------------------------


@dataclass
class AlertView:
    """Flat, read-only view of one alert + its event for rule matching."""

    alert_id: Optional[str]
    event_id: Optional[str]
    event_type: Optional[str]
    severity: Optional[str]
    rule_name: Optional[str]
    detection_method: Optional[str]
    description: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    user: Optional[str]
    host: Optional[str]
    stage: Optional[str]

    @property
    def evidence_ids(self) -> List[str]:
        ids: List[str] = []
        if self.alert_id:
            ids.append(f"alert-{self.alert_id}")
        if self.event_id:
            ids.append(f"event-{self.event_id}")
        return ids


def _first(values: set) -> Optional[str]:
    if not values:
        return None
    return sorted(values)[0]


def build_alert_views(
    alerts: List[Any],
    events_by_alert: Optional[Dict[str, Any]] = None,
) -> List[AlertView]:
    """Normalise Alert models (+ their events) into AlertView records."""
    views: List[AlertView] = []
    for alert in alerts:
        alert_id = getattr(alert, "id", None)
        event = (
            events_by_alert.get(alert_id)
            if events_by_alert
            else getattr(alert, "event", None)
        )

        indicators: Dict[str, set] = {
            "source_ips": set(),
            "destination_ips": set(),
            "users": set(),
            "hosts": set(),
        }
        if event is not None:
            extracted = extract_indicators(event)
            indicators = {
                k: extracted.get(k, set()) for k in indicators
            }

        from app.attack_stages import classify_event

        stage = None
        if event is not None:
            stage = classify_event(event) or classify_event(alert)
        else:
            stage = classify_event(alert)

        views.append(
            AlertView(
                alert_id=alert_id,
                event_id=getattr(event, "id", None) or getattr(alert, "event_id", None),
                event_type=getattr(event, "event_type", None),
                severity=getattr(alert, "severity", None)
                or getattr(event, "severity", None),
                rule_name=getattr(alert, "rule_name", None),
                detection_method=getattr(alert, "detection_source", None),
                description=getattr(alert, "description", None),
                source_ip=_first(indicators["source_ips"]),
                destination_ip=_first(indicators["destination_ips"]),
                user=_first(indicators["users"]),
                host=_first(indicators["hosts"]),
                stage=stage,
            )
        )
    return views


@dataclass
class EngineContext:
    """Everything the deterministic rules are allowed to look at."""

    incident: Any
    views: List[AlertView]
    stages: List[str]
    risk: Optional[Dict[str, Any]]
    investigation: Optional[Dict[str, Any]]
    users: List[str]
    hosts: List[str]
    source_ips: List[str]
    destination_ips: List[str]

    @property
    def risk_level(self) -> str:
        if self.risk and self.risk.get("risk_level"):
            return self.risk["risk_level"]
        return getattr(self.incident, "risk_level", None) or "LOW"

    @property
    def risk_score(self) -> Optional[float]:
        if self.risk and self.risk.get("risk_score") is not None:
            return self.risk["risk_score"]
        return getattr(self.incident, "risk_score", None)

    @property
    def severity(self) -> str:
        return (getattr(self.incident, "severity", None) or "info").lower()


@dataclass
class RuleMatch:
    """A rule that fired, with the evidence that triggered it."""

    rule_key: str
    title: str
    description: str
    category: str
    matched: List[AlertView]
    fragments: List[str] = field(default_factory=list)


def _quote_list(values: List[str], limit: int = 3) -> str:
    shown = [f"'{v}'" for v in values[:limit]]
    text = ", ".join(shown)
    if len(values) > limit:
        text += f" (and {len(values) - limit} more)"
    return text


def _host_fragment(views: List[AlertView], ctx: EngineContext) -> Optional[str]:
    host = next((v.host for v in views if v.host), None) or (
        ctx.hosts[0] if ctx.hosts else None
    )
    return f"host '{host}'" if host else None


# ---------------------------------------------------------------------------
# Rules (each returns a RuleMatch or None)
# ---------------------------------------------------------------------------


def _rule_compromised_account(ctx: EngineContext) -> Optional[RuleMatch]:
    cred_views = [
        v
        for v in ctx.views
        if v.stage == "Credential Access" or v.event_type in CREDENTIAL_EVENT_TYPES
    ]
    if not ctx.users or not cred_views:
        return None
    users = _quote_list(ctx.users)
    return RuleMatch(
        rule_key="compromised-account",
        title="Investigate and consider disabling the affected account(s)",
        description=(
            f"Review authentication history and recent activity for account(s) {users}. "
            "If compromise is confirmed, disable the account or reset its credentials "
            "through your standard account-management process. This recommendation is "
            "advisory; an analyst must approve and perform any account change."
        ),
        category="ACCOUNT_SECURITY",
        matched=cred_views,
        fragments=[f"credential-access activity involving account(s) {users}"],
    )


def _rule_review_privilege_changes(ctx: EngineContext) -> Optional[RuleMatch]:
    priv_views = [
        v
        for v in ctx.views
        if v.stage == "Privilege Escalation"
        or v.event_type in PRIVILEGE_EVENT_TYPES
    ]
    if not priv_views:
        return None
    host_part = _host_fragment(priv_views, ctx)
    fragment = (
        f"potential privilege escalation involving {host_part}"
        if host_part
        else "potential privilege escalation"
    )
    return RuleMatch(
        rule_key="review-privilege-changes",
        title="Review recent privilege and role changes",
        description=(
            "Audit recent privilege, role, and group-membership changes for the "
            "affected users and hosts to determine whether elevated access was "
            "legitimately granted. Revoke any unauthorised elevation through your "
            "approved change process. No change is made automatically."
        ),
        category="PRIVILEGE_MANAGEMENT",
        matched=priv_views,
        fragments=[fragment],
    )


def _rule_isolate_endpoint(ctx: EngineContext) -> Optional[RuleMatch]:
    iso_views = [
        v
        for v in ctx.views
        if v.stage in CONTAINMENT_STAGES or v.event_type in CONTAINMENT_EVENT_TYPES
    ]
    if not ctx.hosts or not iso_views:
        return None
    hosts = _quote_list(ctx.hosts)
    return RuleMatch(
        rule_key="isolate-endpoint",
        title="Consider isolating affected endpoint(s) pending investigation",
        description=(
            f"Evaluate isolating host(s) {hosts} from the network while the incident "
            "is investigated, using your standard containment procedure (for example "
            "EDR isolation or VLAN quarantine). Isolation must be executed by an "
            "approved analyst; Nexus One does not isolate endpoints itself."
        ),
        category="CONTAINMENT",
        matched=iso_views,
        fragments=[f"execution or privilege-elevation evidence on host(s) {hosts}"],
    )


def _rule_investigate_network_indicator(ctx: EngineContext) -> Optional[RuleMatch]:
    ip_views = [v for v in ctx.views if v.source_ip or v.destination_ip]
    if not ctx.source_ips or not ip_views:
        return None
    ips = _quote_list(list(ctx.source_ips))
    return RuleMatch(
        rule_key="investigate-network-indicator",
        title="Investigate suspicious network indicators",
        description=(
            f"Check the observed source IP indicator(s) {ips} against threat-intel "
            "sources and internal logs. If an indicator is confirmed malicious, block "
            "it at the perimeter through your approved change-management process. "
            "Blocking is not performed by Nexus One."
        ),
        category="NETWORK_SECURITY",
        matched=ip_views,
        fragments=[f"network activity involving source IP(s) {ips}"],
    )


def _rule_investigate_data_exfiltration(ctx: EngineContext) -> Optional[RuleMatch]:
    exfil_views = [
        v
        for v in ctx.views
        if v.stage == "Exfiltration" or v.event_type in EXFILTRATION_EVENT_TYPES
    ]
    if not exfil_views:
        return None
    return RuleMatch(
        rule_key="investigate-data-exfiltration",
        title="Investigate potential data exfiltration",
        description=(
            "Review outbound transfer volumes, destinations, and the data involved in "
            "the flagged transfer events. Determine what data left the environment "
            "(if any) and whether it was authorised. Notify the data-protection or "
            "legal team if exfiltration is confirmed."
        ),
        category="DATA_PROTECTION",
        matched=exfil_views,
        fragments=["evidence of large or suspicious data-transfer activity"],
    )


def _rule_monitor_lateral_movement(ctx: EngineContext) -> Optional[RuleMatch]:
    lateral_views = [
        v for v in ctx.views if v.stage == "Lateral Movement" or v.event_type == "lateral_movement"
    ]
    if "Lateral Movement" not in ctx.stages and len(ctx.hosts) < 2:
        return None
    matched = lateral_views or list(ctx.views)
    if len(ctx.hosts) >= 2:
        fragment = f"activity spanning {len(ctx.hosts)} hosts ({_quote_list(ctx.hosts)})"
    else:
        fragment = "explicit lateral-movement evidence"
    return RuleMatch(
        rule_key="monitor-lateral-movement",
        title="Monitor for lateral movement",
        description=(
            "Watch for further authentication or execution activity spreading between "
            "the affected hosts and accounts. Tighten monitoring rules for the observed "
            "source and destination pairs while the investigation is open."
        ),
        category="LATERAL_MOVEMENT",
        matched=matched,
        fragments=[fragment],
    )


def _rule_review_authentication_activity(ctx: EngineContext) -> Optional[RuleMatch]:
    auth_views = [
        v
        for v in ctx.views
        if v.event_type in AUTH_EVENT_TYPES
        or v.stage in ("Credential Access", "Initial Access")
    ]
    if not auth_views:
        return None
    who = _quote_list(ctx.users) if ctx.users else "the affected accounts"
    return RuleMatch(
        rule_key="review-authentication-activity",
        title="Review authentication activity",
        description=(
            f"Pull authentication logs for {who} covering the incident window and "
            "surrounding hours. Look for successful logins from unusual sources, "
            "impossible-travel patterns, or MFA prompts that precede the alerts."
        ),
        category="AUTHENTICATION",
        matched=auth_views,
        fragments=[f"authentication-related events involving {who}"],
    )


def _rule_review_ai_investigation_findings(ctx: EngineContext) -> Optional[RuleMatch]:
    if not ctx.investigation:
        return None
    report = ctx.investigation.get("investigation") or {}
    findings = report.get("investigation_findings") or []
    next_steps = report.get("recommended_next_steps") or []
    if not findings and not next_steps:
        return None

    cited_alert_ids = set()
    for evidence_id in ctx.investigation.get("evidence_ids") or []:
        if isinstance(evidence_id, str) and evidence_id.startswith("alert-"):
            cited_alert_ids.add(evidence_id[len("alert-"):])
    matched = [v for v in ctx.views if v.alert_id in cited_alert_ids] or list(ctx.views)

    return RuleMatch(
        rule_key="review-ai-investigation-findings",
        title="Review AI investigation findings and suggested next steps",
        description=(
            "The AI investigation embedded in this incident is advisory analysis, not "
            "confirmed fact. Review its findings and suggested next steps, validate them "
            f"against the cited evidence ({len(findings)} finding(s), "
            f"{len(next_steps)} suggested next step(s)), and incorporate confirmed items "
            "into the response plan."
        ),
        category="ANALYST_REVIEW",
        matched=matched,
        fragments=[
            f"an AI investigation reporting {len(findings)} finding(s) and "
            f"{len(next_steps)} suggested next step(s)"
        ],
    )


def _rule_collect_additional_evidence(ctx: EngineContext) -> Optional[RuleMatch]:
    fragments: List[str] = []
    if not ctx.investigation:
        fragments.append("no AI investigation has been run for this incident yet")
    else:
        report = ctx.investigation.get("investigation") or {}
        uncertainties = report.get("uncertainties") or []
        truncated = bool(ctx.investigation.get("context_truncated"))
        if uncertainties:
            fragments.append(
                f"{len(uncertainties)} open uncertainty/uncertainties flagged by the investigation"
            )
        if truncated:
            fragments.append("the investigation context was truncated")
        if not fragments:
            return None
    return RuleMatch(
        rule_key="collect-additional-evidence",
        title="Collect additional evidence",
        description=(
            "Close the identified evidence gaps before concluding the investigation: "
            "pull extended logs for the affected hosts/users, enrich the observed "
            "indicators, and capture any telemetry referenced but not included in the "
            "incident."
        ),
        category="EVIDENCE_COLLECTION",
        matched=list(ctx.views),
        fragments=fragments,
    )


def _rule_preserve_logs_for_forensics(ctx: EngineContext) -> Optional[RuleMatch]:
    return RuleMatch(
        rule_key="preserve-logs-for-forensics",
        title="Preserve logs and evidence for forensic follow-up",
        description=(
            "Export and write-protect the relevant logs (authentication, endpoint, "
            "network, and proxy) covering the incident window plus a buffer period, so "
            "evidence is retained even if retention windows expire."
        ),
        category="FORENSICS",
        matched=list(ctx.views),
        fragments=[f"{len(ctx.views)} correlated alert(s) in the incident"],
    )


RULES: List[Callable[[EngineContext], Optional[RuleMatch]]] = [
    _rule_investigate_data_exfiltration,
    _rule_compromised_account,
    _rule_isolate_endpoint,
    _rule_review_privilege_changes,
    _rule_investigate_network_indicator,
    _rule_monitor_lateral_movement,
    _rule_review_authentication_activity,
    _rule_review_ai_investigation_findings,
    _rule_collect_additional_evidence,
    _rule_preserve_logs_for_forensics,
]


# ---------------------------------------------------------------------------
# Priority computation
# ---------------------------------------------------------------------------


def _priority_from_score(score: float) -> str:
    for threshold, level in PRIORITY_LEVELS:
        if score >= threshold:
            return level
    return "LOW"


def _build_rationale(priority: str, score: float, ctx: EngineContext, match: RuleMatch) -> str:
    level_word = {"LOW": "Low", "MEDIUM": "Medium", "HIGH": "High", "CRITICAL": "Critical"}[priority]
    risk_score = ctx.risk_score
    if risk_score is not None:
        risk_part = f"the incident is {ctx.risk_level} risk ({risk_score:.1f}/100)"
    else:
        risk_part = f"the incident is {ctx.risk_level} risk"
    fragments = " and ".join(match.fragments) if match.fragments else "correlated alert activity"
    return (
        f"{level_word} priority because {risk_part} and the evidence contains "
        f"{fragments}. Deterministic priority score {score:.0f}/100."
    )


def _finalize_match(match: RuleMatch, ctx: EngineContext) -> Dict[str, Any]:
    base = RULE_BASE_SCORES[match.rule_key]
    factors: List[str] = [f"rule base score {base:.0f} ({match.rule_key})"]
    score = base

    risk_boost = PRIORITY_WEIGHTS["risk_level_boost"].get(ctx.risk_level, 0.0)
    if risk_boost:
        score += risk_boost
        factors.append(f"incident risk level {ctx.risk_level} +{risk_boost:.0f}")

    severity_boost = PRIORITY_WEIGHTS["severity_boost"].get(ctx.severity, 0.0)
    if severity_boost:
        score += severity_boost
        factors.append(f"incident severity {ctx.severity} +{severity_boost:.0f}")

    matched_count = len(match.matched)
    evidence_boost = min(
        matched_count * PRIORITY_WEIGHTS["evidence_boost_per_alert"],
        PRIORITY_WEIGHTS["evidence_boost_max"],
    )
    if evidence_boost:
        score += evidence_boost
        factors.append(f"{matched_count} supporting alert(s) +{evidence_boost:.0f}")

    if len(ctx.stages) >= 2:
        boost = PRIORITY_WEIGHTS["multi_stage_boost"]
        score += boost
        factors.append(f"multi-stage incident ({len(ctx.stages)} stages) +{boost:.0f}")

    if ctx.investigation:
        boost = PRIORITY_WEIGHTS["investigation_available_boost"]
        score += boost
        factors.append(f"AI investigation available +{boost:.0f}")

    score = max(0.0, min(100.0, score))
    priority = _priority_from_score(score)

    confidence = CONFIDENCE_WEIGHTS["base"] + CONFIDENCE_WEIGHTS["per_matching_alert"] * min(
        matched_count, CONFIDENCE_WEIGHTS["max_matching_alerts"]
    )
    if ctx.investigation:
        confidence += CONFIDENCE_WEIGHTS["investigation_available"]
    confidence = min(confidence, CONFIDENCE_WEIGHTS["cap"])

    evidence_ids = sorted({eid for v in match.matched for eid in v.evidence_ids})

    return {
        "recommendation_id": f"rec-{match.rule_key}",
        "title": match.title,
        "description": match.description,
        "priority": priority,
        "priority_score": round(score, 1),
        "priority_factors": factors,
        "category": match.category,
        "rationale": _build_rationale(priority, score, ctx, match),
        "evidence_ids": evidence_ids,
        "confidence": round(confidence, 2),
        "requires_analyst_approval": True,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_recommendations(
    incident: Any,
    alerts: List[Any],
    events_by_alert: Optional[Dict[str, Any]] = None,
    risk: Optional[Dict[str, Any]] = None,
    investigation: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Generate deterministic recommendations for an incident.

    ``risk`` is the output of ``RiskService.get_risk`` and ``investigation``
    the persisted ``InvestigationService`` record (or None). Returns a list
    of recommendation dicts sorted by descending priority score.
    """
    views = build_alert_views(alerts, events_by_alert)
    if not views:
        return []

    ctx = EngineContext(
        incident=incident,
        views=views,
        stages=get_distinct_stages(alerts),
        risk=risk,
        investigation=investigation,
        users=list(getattr(incident, "users", None) or []),
        hosts=list(getattr(incident, "hosts", None) or []),
        source_ips=list(getattr(incident, "source_ips", None) or []),
        destination_ips=list(getattr(incident, "destination_ips", None) or []),
    )

    recommendations: List[Dict[str, Any]] = []
    for rule in RULES:
        match = rule(ctx)
        if match is not None:
            recommendations.append(_finalize_match(match, ctx))

    recommendations.sort(key=lambda r: (-r["priority_score"], r["recommendation_id"]))
    return recommendations


def valid_evidence_ids(
    alerts: List[Any],
    events_by_alert: Optional[Dict[str, Any]] = None,
) -> set:
    """All evidence IDs the incident legitimately supports (alert-/event-)."""
    ids = set()
    for view in build_alert_views(alerts, events_by_alert):
        ids.update(view.evidence_ids)
    return ids
