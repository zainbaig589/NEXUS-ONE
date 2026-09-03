import { useState } from 'react';
import { api } from '@/api/nexus';
import { useApi } from '@/hooks/useApi';
import SeverityBadge from '@/components/SeverityBadge';
import StatusBadge from '@/components/StatusBadge';
import EvidenceIds from '@/components/EvidenceIds';
import { EmptyState, ErrorBanner, Loading } from '@/components/States';
import {
  formatConfidence,
  formatDateTime,
  formatDuration,
  riskLevelColor,
  shortId,
  stageLabel,
} from '@/utils/format';
import type { IncidentReport, ReportTimelineEntry } from '@/types';

export default function ReportsPage() {
  const incidents = useApi(() => api.listIncidents({ limit: 200 }), [], { pollMs: 60_000 });
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const effectiveId = selectedId ?? incidents.data?.[0]?.id ?? null;

  const report = useApi(
    () => (effectiveId ? api.getReport(effectiveId) : Promise.resolve(null)),
    [effectiveId],
  );

  const [generating, setGenerating] = useState(false);
  const [generateError, setGenerateError] = useState<string | null>(null);
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  async function generateReport(incidentId: string) {
    setGenerating(true);
    setGenerateError(null);
    try {
      await api.generateReport(incidentId);
      report.refresh();
    } catch (err) {
      setGenerateError(err instanceof Error ? err.message : String(err));
    } finally {
      setGenerating(false);
    }
  }

  async function downloadPdf(incidentId: string) {
    setDownloadingPdf(true);
    setGenerateError(null);
    try {
      const blob = await api.getReportPdf(incidentId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `nexus-one-report-${incidentId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      setGenerateError(err instanceof Error ? err.message : String(err));
    } finally {
      setDownloadingPdf(false);
    }
  }

  const reportData = report.data;
  const isDemo =
    reportData?.analysis.investigation_metadata?.analysis_mode?.toUpperCase().includes('DEMO') ??
    false;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Report Center</h1>
          <p className="page-subtitle">
            Incident reports with observed evidence, analysis, and recommended actions.
          </p>
        </div>
        <div className="page-actions">
          <button
            type="button"
            className="btn"
            onClick={() => void incidents.refresh()}
            disabled={incidents.refreshing}
          >
            {incidents.refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      {incidents.error ? <ErrorBanner message={incidents.error} onRetry={incidents.refresh} /> : null}

      {incidents.loading ? (
        <Loading label="Loading incidents…" />
      ) : (incidents.data ?? []).length === 0 ? (
        <EmptyState
          title="No incidents available"
          hint="Run the attack scenario from the dashboard to create incidents."
        />
      ) : (
        <>
          <section className="panel" style={{ marginBottom: 16 }} data-testid="reports-incident-table">
            <h2 className="panel-title">Incidents</h2>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Incident ID</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Alerts</th>
                    <th>Report</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {(incidents.data ?? []).map((incident) => {
                    const isSelected = incident.id === effectiveId;
                    const hasReport =
                      isSelected && reportData && reportData.incident_id === incident.id;
                    return (
                      <tr
                        key={incident.id}
                        className={isSelected ? 'report-row selected' : 'report-row'}
                        data-testid="report-incident-row"
                      >
                        <td className="mono">{incident.id.slice(0, 8)}</td>
                        <td>{incident.title}</td>
                        <td>
                          <SeverityBadge severity={incident.severity} />
                        </td>
                        <td>
                          <StatusBadge status={incident.status} />
                        </td>
                        <td className="num">{incident.alert_count}</td>
                        <td>
                          {hasReport ? (
                            <span className="badge badge-open" style={{ textTransform: 'none' }}>
                              Generated
                            </span>
                          ) : isSelected ? (
                            <span className="badge badge-neutral">None</span>
                          ) : (
                            <span style={{ color: 'var(--text-dim)' }}>—</span>
                          )}
                        </td>
                        <td>
                          <span style={{ display: 'flex', gap: 8 }}>
                            <button
                              type="button"
                              className="btn btn-sm"
                              onClick={() => setSelectedId(incident.id)}
                              data-testid="view-report-button"
                            >
                              View Report
                            </button>
                            <button
                              type="button"
                              className="btn btn-sm btn-primary"
                              onClick={() => {
                                setSelectedId(incident.id);
                                void generateReport(incident.id);
                              }}
                              disabled={generating}
                              data-testid="generate-report-row-button"
                            >
                              Generate Report
                            </button>
                            <button
                              type="button"
                              className="btn btn-sm"
                              onClick={() => void downloadPdf(incident.id)}
                              disabled={downloadingPdf}
                              data-testid="download-pdf-row-button"
                            >
                              PDF
                            </button>
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>

          {generateError ? <ErrorBanner message={generateError} /> : null}
          {report.error ? <ErrorBanner message={report.error} onRetry={report.refresh} /> : null}

          <section className="panel" data-testid="report-detail">
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 12,
                flexWrap: 'wrap',
                marginBottom: 14,
              }}
            >
              <h2 className="panel-title" style={{ marginBottom: 0 }}>
                {reportData ? reportData.title : 'Incident Report'}
              </h2>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                {reportData?.analysis.investigation_metadata ? (
                  <span className={`badge ${isDemo ? 'badge-demo' : 'badge-live'}`}>
                    {isDemo ? 'DEMO MODE' : 'LIVE LLM'}
                  </span>
                ) : null}
                <button
                  type="button"
                  className="btn"
                  onClick={() => effectiveId && void downloadPdf(effectiveId)}
                  disabled={downloadingPdf || !effectiveId}
                  data-testid="download-pdf-button"
                >
                  {downloadingPdf ? 'Downloading…' : 'Download PDF'}
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => effectiveId && void generateReport(effectiveId)}
                  disabled={generating || !effectiveId}
                  data-testid="generate-report-button"
                >
                  {generating ? 'Generating…' : reportData ? 'Regenerate Report' : 'Generate Report'}
                </button>
              </div>
            </div>

            {report.loading ? (
              <Loading label="Loading report…" />
            ) : reportData ? (
              <ReportBody report={reportData} />
            ) : (
              <EmptyState
                title="No report generated for this incident"
                hint="Click Generate Report to produce a full incident report."
              />
            )}
          </section>
        </>
      )}
    </div>
  );
}

function ReportBody({ report }: { report: IncidentReport }) {
  const observed = report.observed_evidence;
  const analysis = report.analysis;
  const meta = analysis.investigation_metadata;
  const ai = analysis.ai_investigation;
  const risk = analysis.deterministic_risk_assessment as
    | { risk_score?: number; risk_level?: string }
    | undefined
    | null;
  const timelineEntries = observed.attack_timeline.entries;
  const duration = observed.incident.duration_seconds;

  return (
    <div>
      <div className="meta-line" style={{ marginBottom: 14 }}>
        <span>
          Report ID: <b className="mono">{shortId(report.report_id, 12)}</b>
        </span>
        <span>Generated: {formatDateTime(report.generated_at)}</span>
        <span>Format v{report.format_version}</span>
        {duration != null ? <span>Duration: {formatDuration(duration)}</span> : null}
      </div>

      <div className="finding-card" data-testid="report-summary">
        <h3 className="panel-title" style={{ marginBottom: 6 }}>
          Summary
        </h3>
        <p style={{ color: 'var(--text-muted)' }}>{report.report_summary}</p>
      </div>

      <h3 className="panel-title">Incident</h3>
      <div className="info-grid" data-testid="report-incident-info">
        <div className="info-row">
          <span className="info-label">Incident</span>
          <span className="info-value mono">{observed.incident.incident_id}</span>
        </div>
        <div className="info-row">
          <span className="info-label">Severity</span>
          <span className="info-value">
            <SeverityBadge severity={observed.incident.severity ?? ''} />
          </span>
        </div>
        <div className="info-row">
          <span className="info-label">Risk Score</span>
          <span className="info-value">
            {risk?.risk_score != null ? (
              <span
                className="mono"
                style={{ color: riskLevelColor(risk.risk_level ?? ''), fontWeight: 600 }}
              >
                {risk.risk_score.toFixed(1)} ({risk.risk_level})
              </span>
            ) : (
              '—'
            )}
          </span>
        </div>
        <div className="info-row">
          <span className="info-label">Status</span>
          <span className="info-value">
            <StatusBadge status={observed.incident.status ?? ''} />
          </span>
        </div>
        <div className="info-row">
          <span className="info-label">Alerts</span>
          <span className="info-value mono">{observed.incident.alert_count}</span>
        </div>
        <div className="info-row">
          <span className="info-label">First Seen</span>
          <span className="info-value">{formatDateTime(observed.incident.first_seen)}</span>
        </div>
        <div className="info-row">
          <span className="info-label">Last Seen</span>
          <span className="info-value">{formatDateTime(observed.incident.last_seen)}</span>
        </div>
        <div className="info-row">
          <span className="info-label">Correlation Score</span>
          <span className="info-value mono">
            {observed.incident.correlation_score != null
              ? observed.incident.correlation_score.toFixed(2)
              : '—'}
          </span>
        </div>
      </div>

      <h3 className="panel-title">Alerts</h3>
      {observed.correlated_alerts.length > 0 ? (
        <div className="table-wrap" data-testid="report-alerts">
          <table>
            <thead>
              <tr>
                <th>Alert</th>
                <th>Rule</th>
                <th>Severity</th>
                <th>Method</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {observed.correlated_alerts.map((alert, i) => (
                <tr key={alert.alert_id ?? i}>
                  <td className="mono">{shortId(alert.alert_id ?? '', 10)}</td>
                  <td>{alert.rule_name ?? '—'}</td>
                  <td>
                    <SeverityBadge severity={alert.severity ?? ''} />
                  </td>
                  <td>
                    <span className="badge badge-neutral">
                      {alert.detection_method === 'ml' ? 'ML' : 'RULE'}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-muted)' }}>{alert.description ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p style={{ color: 'var(--text-muted)' }}>No correlated alert detail recorded.</p>
      )}

      <h3 className="panel-title">Timeline</h3>
      {timelineEntries.length > 0 ? (
        <div className="table-wrap" data-testid="report-timeline">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Event</th>
                <th>Severity</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>User</th>
                <th>Host</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {timelineEntries.map((entry: ReportTimelineEntry, i) => (
                <tr key={entry.alert_id ?? entry.event_id ?? i}>
                  <td className="mono" style={{ color: 'var(--text-muted)' }}>
                    {formatDateTime(entry.timestamp)}
                  </td>
                  <td className="mono">{entry.event_type ?? '—'}</td>
                  <td>
                    <SeverityBadge severity={entry.severity ?? ''} />
                  </td>
                  <td className="mono">{entry.source_ip ?? '—'}</td>
                  <td className="mono">{entry.destination_ip ?? '—'}</td>
                  <td className="mono">{entry.user ?? '—'}</td>
                  <td className="mono">{entry.host ?? '—'}</td>
                  <td style={{ color: 'var(--text-muted)' }}>{entry.description ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p style={{ color: 'var(--text-muted)' }}>
          First seen {formatDateTime(observed.attack_timeline.first_seen)} · last seen{' '}
          {formatDateTime(observed.attack_timeline.last_seen)}.
        </p>
      )}

      {analysis.potential_attack_stages.length > 0 ? (
        <>
          <h3 className="panel-title">Attack Stages</h3>
          <div className="stage-list" data-testid="report-stages">
            {analysis.potential_attack_stages.map((stage) => (
              <span key={stage} className="badge badge-neutral">
                {stageLabel(stage)}
              </span>
            ))}
          </div>
        </>
      ) : null}

      {report.evidence_references.length > 0 ? (
        <>
          <h3 className="panel-title">Evidence</h3>
          <div data-testid="report-evidence" style={{ marginBottom: 12 }}>
            <EvidenceIds ids={report.evidence_references} />
          </div>
        </>
      ) : null}

      <h3 className="panel-title">AI Investigation</h3>
      {ai ? (
        <div className="finding-card" data-testid="report-ai-investigation">
          <div className="meta-line" style={{ marginBottom: 10 }}>
            {meta ? (
              <>
                <span>
                  Provider: <b>{meta.provider}</b>
                </span>
                <span>Generated: {formatDateTime(meta.generated_at)}</span>
                <span>Confidence: {formatConfidence(meta.confidence)}</span>
              </>
            ) : null}
          </div>
          <p style={{ color: 'var(--text-muted)' }}>{ai.incident_summary}</p>
          <p style={{ color: 'var(--text-muted)', marginTop: 8 }}>{ai.threat_assessment}</p>
          {ai.attack_narrative ? (
            <p style={{ color: 'var(--text-muted)', marginTop: 8 }}>{ai.attack_narrative}</p>
          ) : null}
        </div>
      ) : (
        <p style={{ color: 'var(--text-muted)' }} data-testid="report-ai-investigation">
          No AI investigation was attached to this report ({analysis.investigation_status}).
        </p>
      )}

      <h3 className="panel-title">Recommendations</h3>
      {report.recommended_actions.recommendations.length > 0 ? (
        <div data-testid="report-recommendations">
          {report.recommended_actions.recommendations.map((rec) => (
            <div className="finding-card" key={rec.recommendation_id}>
              <div style={{ display: 'flex', gap: 10, alignItems: 'baseline', flexWrap: 'wrap' }}>
                <span
                  className="badge badge-neutral"
                  style={{ color: riskLevelColor(rec.priority), borderColor: riskLevelColor(rec.priority) }}
                >
                  {rec.priority}
                </span>
                <span style={{ fontWeight: 600 }}>{rec.title}</span>
                <span className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                  {rec.category}
                </span>
              </div>
              <p style={{ color: 'var(--text-muted)', marginTop: 6 }}>{rec.description}</p>
              <p style={{ color: 'var(--text-dim)', fontSize: 12, marginTop: 4 }}>{rec.rationale}</p>
            </div>
          ))}
          <p className="notice notice-info" style={{ marginTop: 10 }}>
            {report.recommended_actions.advisory_notice}
          </p>
        </div>
      ) : (
        <p style={{ color: 'var(--text-muted)' }}>No recommended actions recorded.</p>
      )}
    </div>
  );
}
