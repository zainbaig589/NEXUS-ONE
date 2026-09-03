/**
 * Typed Nexus One API surface. All network access in the app goes through
 * this module — components never call fetch directly.
 */

import { http, ApiError } from './client';
import type {
  Alert,
  CorrelationResponse,
  DemoAttackScenarioResponse,
  EventCreate,
  Health,
  Incident,
  IncidentReport,
  IncidentSummary,
  InvestigationResponse,
  MLStatus,
  MLTrainResult,
  RecommendationsResponse,
  RiskAssessment,
  Rule,
  SecurityEvent,
  Timeline,
} from '@/types';
import { buildAttackScenarioEvents } from './scenario';

export type IncidentListParams = {
  status?: string;
  limit?: number;
};

export type AlertListParams = {
  severity?: string;
  status?: string;
  limit?: number;
};

export type RuleListParams = {
  enabledOnly?: boolean;
  limit?: number;
};

export type EventListParams = {
  limit?: number;
};

function withQuery(path: string, params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `${path}?${qs}` : path;
}

export const api = {
  health: () => http.get<Health>('/health'),

  listIncidents: (params: IncidentListParams = {}) =>
    http.get<Incident[]>(withQuery('/api/v1/incidents/', params)),

  getIncident: (incidentId: string) =>
    http.get<Incident>(`/api/v1/incidents/${incidentId}`),

  getIncidentSummary: (incidentId: string) =>
    http.get<IncidentSummary>(`/api/v1/incidents/${incidentId}/summary`),

  getIncidentAlerts: (incidentId: string) =>
    http.get<Alert[]>(`/api/v1/incidents/${incidentId}/alerts`),

  getIncidentRisk: (incidentId: string) =>
    http.get<RiskAssessment>(`/api/v1/incidents/${incidentId}/risk`),

  getIncidentTimeline: (incidentId: string) =>
    http.get<Timeline>(`/api/v1/incidents/${incidentId}/timeline`),

  listAlerts: (params: AlertListParams = {}) =>
    http.get<Alert[]>(
      withQuery('/api/v1/alerts/', {
        severity: params.severity,
        status_filter: params.status,
        limit: params.limit,
      }),
    ),

  /** Raw security events (pre-detection telemetry). */
  listEvents: (params: EventListParams = {}) =>
    http.get<SecurityEvent[]>(withQuery('/api/v1/events/', { limit: params.limit })),

  /** Detection rule catalog. */
  listRules: (params: RuleListParams = {}) =>
    http.get<Rule[]>(
      withQuery('/api/v1/rules/', {
        enabled_only: params.enabledOnly ? 'true' : undefined,
        limit: params.limit,
      }),
    ),

  /** Enable or disable a detection rule. */
  toggleRule: (ruleId: string, enabled: boolean) =>
    http.patch<Rule>(`/api/v1/rules/${ruleId}/toggle?enabled=${enabled}`),

  /** Current Isolation Forest model status. */
  mlStatus: () => http.get<MLStatus>('/api/v1/ml/status'),

  /** Retrain the anomaly-detection model on the synthetic dataset. */
  trainMl: () => http.post<MLTrainResult>('/api/v1/ml/train'),

  /** Update an incident's lifecycle status. */
  updateIncidentStatus: (incidentId: string, status: string) =>
    http.patch<Incident>(`/api/v1/incidents/${incidentId}/status?status=${encodeURIComponent(status)}`),

  /** Run an AI investigation for the incident (provider per backend config). */
  investigate: (incidentId: string) =>
    http.post<InvestigationResponse>(`/api/v1/incidents/${incidentId}/investigate`),

  /** Latest persisted investigation, or null when none has been run yet. */
  getInvestigation: async (incidentId: string): Promise<InvestigationResponse | null> => {
    try {
      return await http.get<InvestigationResponse>(
        `/api/v1/incidents/${incidentId}/investigation`,
      );
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) return null;
      throw error;
    }
  },

  getRecommendations: (incidentId: string) =>
    http.get<RecommendationsResponse>(`/api/v1/incidents/${incidentId}/recommendations`),

  generateReport: (incidentId: string) =>
    http.post<IncidentReport>(`/api/v1/incidents/${incidentId}/report`),

  /** Latest persisted report, or null when none has been generated yet. */
  getReport: async (incidentId: string): Promise<IncidentReport | null> => {
    try {
      return await http.get<IncidentReport>(`/api/v1/incidents/${incidentId}/report`);
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) return null;
      throw error;
    }
  },

  /** Persisted report rendered as HTML; generates one first if none exists. */
  getReportHtml: async (incidentId: string): Promise<string> => {
    try {
      return await http.getText(`/api/v1/incidents/${incidentId}/report?format=html`);
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        return http.postText(`/api/v1/incidents/${incidentId}/report?format=html`);
      }
      throw error;
    }
  },

  /** Download the report as a PDF document. */
  getReportPdf: (incidentId: string) =>
    http.getBlob(`/api/v1/incidents/${incidentId}/report?format=pdf`),

  ingestEvents: (events: EventCreate[]) =>
    Promise.all(events.map((event) => http.post('/api/v1/events/', event))),

  processDetection: () => http.post('/api/v1/detection/process'),

  correlate: () =>
    http.post<CorrelationResponse>('/api/v1/incidents/correlate', {}),

  /**
   * Ingest the canonical multi-stage attack scenario (brute force →
   * privilege escalation → exfiltration) through the live API, then run
   * detection and correlation. Returns the incident IDs that were touched.
   */
  runAttackScenario: async (): Promise<string[]> => {
    await api.ingestEvents(buildAttackScenarioEvents());
    await api.processDetection();
    const correlation = await api.correlate();
    return correlation.incident_ids;
  },

  /** One-click full-pipeline demo: ingest → detect → correlate → investigate → recommend → report. */
  runDemoScenario: () =>
    http.post<DemoAttackScenarioResponse>('/api/v1/demo/attack-scenario'),
};

export { ApiError } from './client';
