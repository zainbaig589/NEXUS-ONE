import { useState } from 'react';
import EvidenceIds from '@/components/EvidenceIds';
import { EmptyState, ErrorBanner, Loading } from '@/components/States';
import { api, ApiError } from '@/api/nexus';
import { formatDateTime, stageLabel } from '@/utils/format';
import type { IncidentReport } from '@/types';

export default function ReportPanel({
  incidentId,
  report,
  loading,
  error,
  onGenerated,
  onRetry,
}: {
  incidentId: string;
  report: IncidentReport | null;
  loading: boolean;
  error: string | null;
  onGenerated: (report: IncidentReport) => void;
  onRetry?: () => void;
}) {
  const [generating, setGenerating] = useState(false);
  const [generateError, setGenerateError] = useState<string | null>(null);
  const [htmlReport, setHtmlReport] = useState<string | null>(null);
  const [htmlLoading, setHtmlLoading] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  async function generate() {
    setGenerating(true);
    setGenerateError(null);
    try {
      const fresh = await api.generateReport(incidentId);
      onGenerated(fresh);
    } catch (err) {
      setGenerateError(err instanceof ApiError ? err.message : 'Failed to generate report.');
    } finally {
      setGenerating(false);
    }
  }

  async function viewHtml() {
    setHtmlLoading(true);
    try {
      setHtmlReport(await api.getReportHtml(incidentId));
    } finally {
      setHtmlLoading(false);
    }
  }

  async function downloadPdf() {
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

  return (
    <section className="panel" data-testid="report-panel">
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
          Incident Report
        </h2>
        <div style={{ display: 'flex', gap: 10 }}>
          <button
            type="button"
            className="btn"
            onClick={() => void viewHtml()}
            disabled={htmlLoading || generating}
            data-testid="view-html-report"
          >
            {htmlLoading ? 'Loading...' : 'View Report (HTML)'}
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => void downloadPdf()}
            disabled={downloadingPdf || generating}
            data-testid="download-pdf-report-panel"
          >
            {downloadingPdf ? 'Preparing PDF...' : 'Download PDF'}
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => void generate()}
            disabled={generating}
            data-testid="generate-report"
          >
            {generating ? 'Generating...' : 'Generate Report'}
          </button>
        </div>
      </div>

      {error ? <ErrorBanner message={error} onRetry={onRetry} /> : null}
      {generateError ? <ErrorBanner message={generateError} onRetry={() => void generate()} /> : null}

      {htmlReport ? (
        <iframe
          className="report-frame"
          title="Incident report (HTML)"
          srcDoc={htmlReport}
          data-testid="report-html-frame"
          sandbox=""
        />
      ) : loading ? (
        <Loading label="Loading report…" />
      ) : !report ? (
        <EmptyState
          title="No report generated yet"
          hint="Click Generate Report to create a structured incident report."
        />
      ) : (
        <div data-testid="report-content">
          <div className="meta-line" style={{ marginBottom: 14 }}>
            <span>Report ID: {report.report_id.slice(0, 8)}</span>
            <span>Generated: {formatDateTime(report.generated_at)}</span>
            <span>Format v{report.format_version}</span>
          </div>
          <p className="report-summary" data-testid="report-summary">
            {report.report_summary}
          </p>

          <h3 className="panel-title" style={{ marginTop: 16 }}>
            Analysis Status
          </h3>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <span className="badge badge-neutral">
              investigation: {report.analysis.investigation_status.replace(/_/g, ' ')}
            </span>
            {report.analysis.potential_attack_stages.map((stage) => (
              <span key={stage} className="badge badge-neutral">
                {stageLabel(stage)}
              </span>
            ))}
          </div>

          <h3 className="panel-title" style={{ marginTop: 16 }}>
            Recommended Actions
          </h3>
          {report.recommended_actions.recommendations.length === 0 ? (
            <p style={{ color: 'var(--text-dim)', fontSize: 13 }}>No recommended actions.</p>
          ) : (
            <ul className="factor-list">
              {report.recommended_actions.recommendations.map((reco) => (
                <li key={reco.recommendation_id}>
                  <span>
                    <strong style={{ color: 'var(--text)' }}>{reco.priority}</strong> — {reco.title}
                  </span>
                </li>
              ))}
            </ul>
          )}

          <h3 className="panel-title" style={{ marginTop: 16 }}>
            Evidence References
          </h3>
          <EvidenceIds ids={report.evidence_references} emptyLabel="none" />
        </div>
      )}
    </section>
  );
}
