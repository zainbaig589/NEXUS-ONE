import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api, ApiError } from '@/api/nexus';
import { useApi } from '@/hooks/useApi';
import SeverityBadge from '@/components/SeverityBadge';
import StatusBadge from '@/components/StatusBadge';
import { ErrorBanner, Loading } from '@/components/States';
import AttackStages from '@/components/detail/AttackStages';
import AttackTimeline from '@/components/detail/AttackTimeline';
import AlertsEvidenceTable from '@/components/detail/AlertsEvidenceTable';
import InvestigationPanel from '@/components/detail/InvestigationPanel';
import RecommendationsPanel from '@/components/detail/RecommendationsPanel';
import ReportPanel from '@/components/detail/ReportPanel';
import RiskPanel from '@/components/detail/RiskPanel';
import { formatDateTime, riskLevelColor } from '@/utils/format';
import type { IncidentReport } from '@/types';

export default function IncidentDetailPage() {
  const { incidentId = '' } = useParams<{ incidentId: string }>();

  const summary = useApi(() => api.getIncidentSummary(incidentId), [incidentId]);
  const alerts = useApi(() => api.getIncidentAlerts(incidentId), [incidentId]);
  const investigation = useApi(() => api.getInvestigation(incidentId), [incidentId]);
  const recommendations = useApi(() => api.getRecommendations(incidentId), [incidentId]);
  const report = useApi(() => api.getReport(incidentId), [incidentId]);

  const [runningInvestigation, setRunningInvestigation] = useState(false);
  const [investigationError, setInvestigationError] = useState<string | null>(null);

  async function runInvestigation() {
    setRunningInvestigation(true);
    setInvestigationError(null);
    try {
      await api.investigate(incidentId);
      await Promise.all([investigation.refresh(), recommendations.refresh(), report.refresh()]);
    } catch (err) {
      setInvestigationError(
        err instanceof ApiError ? err.message : 'Failed to run AI investigation.',
      );
    } finally {
      setRunningInvestigation(false);
    }
  }

  if (summary.loading) {
    return <Loading label="Loading incident…" />;
  }

  if (summary.error) {
    return <ErrorBanner message={summary.error} onRetry={summary.refresh} />;
  }

  const incident = summary.data?.incident;
  const risk = summary.data?.risk ?? null;
  const timeline = summary.data?.timeline ?? null;
  const stages = incident?.attack_stages ?? [];

  if (!incident) {
    return <ErrorBanner message="Incident not found." />;
  }

  return (
    <div>
      <Link to="/incidents" className="back-link">
        ← Back to incidents
      </Link>

      <header className="detail-header" data-testid="incident-header">
        <div className="detail-title-row">
          <h1 className="detail-title">{incident.title}</h1>
          <SeverityBadge severity={incident.severity} />
          <StatusBadge status={incident.status} />
          {incident.risk_score != null ? (
            <span
              className="badge badge-neutral mono"
              style={{
                color: riskLevelColor(incident.risk_level),
                borderColor: riskLevelColor(incident.risk_level),
              }}
              data-testid="header-risk"
            >
              RISK {incident.risk_score.toFixed(1)} {incident.risk_level}
            </span>
          ) : null}
        </div>
        <div className="detail-meta">
          <span>id: {incident.id}</span>
          <span>first seen: {formatDateTime(incident.first_seen)}</span>
          <span>last seen: {formatDateTime(incident.last_seen)}</span>
          <span>alerts: {incident.alert_count}</span>
          {incident.correlation_score != null ? (
            <span>correlation: {incident.correlation_score.toFixed(2)}</span>
          ) : null}
        </div>
        {incident.correlation_reasons.length > 0 ? (
          <div className="meta-line">
            {incident.correlation_reasons.map((reason) => (
              <span key={reason} className="badge badge-neutral">
                {reason}
              </span>
            ))}
          </div>
        ) : null}
      </header>

      {alerts.error ? <ErrorBanner message={alerts.error} onRetry={alerts.refresh} /> : null}

      <div className="grid grid-detail">
        <AttackTimeline timeline={timeline} />
        <div>
          <RiskPanel risk={risk} />
          <div style={{ height: 16 }} />
          <AttackStages stages={stages} />
        </div>
      </div>

      <div style={{ height: 16 }} />

      <AlertsEvidenceTable alerts={alerts.data ?? []} />

      <div style={{ height: 16 }} />

      <InvestigationPanel
        investigation={investigation.data}
        running={runningInvestigation}
        error={investigation.error ?? investigationError}
        onRun={() => void runInvestigation()}
        disabled={investigation.loading}
      />

      <div style={{ height: 16 }} />

      <RecommendationsPanel
        recommendations={recommendations.data}
        loading={recommendations.loading}
        error={recommendations.error}
        onRetry={recommendations.refresh}
      />

      <div style={{ height: 16 }} />

      <ReportPanel
        incidentId={incidentId}
        report={report.data}
        loading={report.loading}
        error={report.error}
        onGenerated={(fresh: IncidentReport) => report.setData(fresh)}
        onRetry={report.refresh}
      />
    </div>
  );
}
