/** TypeScript types mirroring the Nexus One backend API responses. */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type Priority = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Health {
  status: string;
  app_name: string;
  version: string;
  environment: string;
  database: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: string;
  description?: string | null;
  status: string;
  alert_ids: string[];
  alert_count: number;
  correlation_score?: number | null;
  correlation_reasons: string[];
  first_seen?: string | null;
  last_seen?: string | null;
  source_ips: string[];
  destination_ips: string[];
  users: string[];
  hosts: string[];
  risk_score?: number | null;
  risk_level: string;
  risk_factors: string[];
  attack_stages: string[];
  created_at: string;
  updated_at: string;
}

export interface Alert {
  id: string;
  event_id: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  description?: string | null;
  status: string;
  detection_source: string;
  created_at: string;
}

export interface RiskAssessment {
  incident_id?: string | null;
  risk_score: number;
  risk_level: RiskLevel;
  contributing_factors: string[];
  scoring_explanation: string;
}

export interface TimelineEntry {
  timestamp?: string | null;
  event_id?: string | null;
  alert_id?: string | null;
  event_type?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  user?: string | null;
  host?: string | null;
  severity: string;
  detection_method: string;
  description?: string | null;
  stage?: string | null;
}

export interface Timeline {
  incident_id?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  duration_seconds: number;
  entries: TimelineEntry[];
}

export interface IncidentSummary {
  incident: Incident;
  risk: RiskAssessment;
  timeline: Timeline;
  potential_attack_stages: string[];
  related_alert_ids: string[];
}

export interface EvidenceItem {
  description: string;
  evidence_ids: string[];
}

export interface InvestigationFinding {
  title: string;
  detail: string;
  evidence_ids: string[];
}

export interface InvestigationReport {
  incident_summary: string;
  threat_assessment: string;
  evidence: EvidenceItem[];
  attack_narrative: string;
  potential_attack_stages: string[];
  affected_entities: string[];
  investigation_findings: InvestigationFinding[];
  uncertainties: string[];
  recommended_next_steps: string[];
  confidence: number;
}

export interface InvestigationResponse {
  incident_id: string;
  provider: string;
  analysis_mode: string;
  generated_at: string;
  investigation: InvestigationReport;
  evidence_ids: string[];
  context_truncated: boolean;
  risk_snapshot?: Record<string, unknown> | null;
}

export interface ResponseRecommendation {
  recommendation_id: string;
  title: string;
  description: string;
  priority: Priority;
  priority_score: number;
  priority_factors: string[];
  category: string;
  rationale: string;
  evidence_ids: string[];
  confidence: number;
  requires_analyst_approval: boolean;
}

export interface RecommendationsResponse {
  incident_id: string;
  generated_at: string;
  advisory_notice: string;
  risk_snapshot?: Record<string, unknown> | null;
  recommendation_count: number;
  recommendations: ResponseRecommendation[];
}

export interface ReportIncidentInfo {
  incident_id: string;
  title?: string | null;
  status?: string | null;
  severity?: string | null;
  description?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  duration_seconds: number;
  alert_count: number;
  correlation_score?: number | null;
  correlation_reasons: string[];
}

export interface ReportAlertSummary {
  alert_id?: string | null;
  event_id?: string | null;
  evidence_ids: string[];
  timestamp?: string | null;
  event_type?: string | null;
  rule_name?: string | null;
  severity?: string | null;
  detection_method?: string | null;
  description?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  user?: string | null;
  host?: string | null;
  potential_attack_stage?: string | null;
}

export interface ReportTimelineEntry {
  timestamp?: string | null;
  event_id?: string | null;
  alert_id?: string | null;
  event_type?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  user?: string | null;
  host?: string | null;
  severity?: string | null;
  detection_method?: string | null;
  description?: string | null;
  stage?: string | null;
}

export interface ReportTimeline {
  first_seen?: string | null;
  last_seen?: string | null;
  duration_seconds: number;
  entries: ReportTimelineEntry[];
}

export interface ReportObservedEvidence {
  incident: ReportIncidentInfo;
  affected_users: string[];
  affected_hosts: string[];
  source_ips: string[];
  destination_ips: string[];
  correlated_alerts: ReportAlertSummary[];
  detection_methods: string[];
  attack_timeline: ReportTimeline;
}

export interface ReportInvestigationMetadata {
  provider: string;
  analysis_mode: string;
  generated_at: string;
  confidence?: number | null;
}

export interface ReportAnalysis {
  analysis_notice: string;
  deterministic_risk_assessment?: Record<string, unknown> | null;
  potential_attack_stages: string[];
  ai_investigation?: InvestigationReport | null;
  investigation_metadata?: ReportInvestigationMetadata | null;
  investigation_status: string;
  uncertainties: string[];
}

export interface ReportRecommendedActions {
  advisory_notice: string;
  all_actions_require_analyst_approval: boolean;
  recommendations: ResponseRecommendation[];
}

export interface IncidentReport {
  report_id: string;
  incident_id: string;
  generated_at: string;
  format_version: string;
  title: string;
  report_summary: string;
  evidence_references: string[];
  observed_evidence: ReportObservedEvidence;
  analysis: ReportAnalysis;
  recommended_actions: ReportRecommendedActions;
}

export interface CorrelationResponse {
  incidents_touched: number;
  incidents_created: number;
  incidents_updated: number;
  incident_ids: string[];
}

export interface Rule {
  id: string;
  name: string;
  description?: string | null;
  rule_type: string;
  severity: string;
  conditions: Record<string, unknown>;
  threshold?: number | null;
  enabled: boolean;
  created_at: string;
}

export interface SecurityEvent {
  id: string;
  source: string;
  event_type: string;
  severity: string;
  payload: Record<string, unknown>;
  timestamp: string;
  processed: boolean;
  created_at: string;
}

export interface MLStatus {
  model_loaded: boolean;
  model_path: string | null;
  training_samples: number | null;
  features: string[];
  threshold: number;
  detection_method: string;
}

export interface MLTrainResult {
  status: string;
  samples_trained: number;
  model_path: string;
  message: string;
}

export interface EventCreate {
  source: string;
  event_type: string;
  severity: string;
  payload: Record<string, unknown>;
  timestamp?: string;
}

export interface DemoStageResult {
  stage: string;
  status: 'success' | 'error' | 'skipped';
  duration_ms: number;
  details: Record<string, unknown>;
  error?: string | null;
}

export interface DemoAttackScenarioResponse {
  demo_run_id: string;
  executed_at: string;
  total_duration_ms: number;
  stages: DemoStageResult[];
  events_created: number;
  alerts_created: number;
  rule_detections: number;
  ml_detections: number;
  incidents_created: number;
  incident_ids: string[];
  primary_incident_id: string | null;
  risk_score: number | null;
  risk_level: string | null;
  investigation_status: string;
  recommendation_count: number;
  report_generated: boolean;
  attack_stages: string[];
}
