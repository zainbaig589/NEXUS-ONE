import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '@/api/nexus';
import { useApi } from '@/hooks/useApi';
import SeverityBadge from '@/components/SeverityBadge';
import StatusBadge from '@/components/StatusBadge';
import EvidenceIds from '@/components/EvidenceIds';
import InvestigationPanel from '@/components/detail/InvestigationPanel';
import { EmptyState, ErrorBanner, Loading } from '@/components/States';
import { formatDateTime, riskLevelColor, stageLabel } from '@/utils/format';

const PROGRESS_MESSAGES = [
  'Collecting incident evidence…',
  'Analyzing attack chain…',
  'Correlating alerts and events…',
  'Evaluating threat indicators…',
  'Generating investigation report…',
];

function useProgressMessage(active: boolean) {
  const [index, setIndex] = useState(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (active) {
      setIndex(0);
      intervalRef.current = setInterval(() => {
        setIndex((prev) => (prev + 1) % PROGRESS_MESSAGES.length);
      }, 2200);
    } else {
      if (intervalRef.current) clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [active]);

  return active ? PROGRESS_MESSAGES[index] : null;
}

export default function AiInvestigatorPage() {
  const incidents = useApi(() => api.listIncidents({ limit: 200 }), [], { pollMs: 30_000 });
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const effectiveId = selectedId ?? incidents.data?.[0]?.id ?? null;
  const selected = (incidents.data ?? []).find((i) => i.id === effectiveId) ?? null;

  const summary = useApi(
    () => (effectiveId ? api.getIncidentSummary(effectiveId) : Promise.resolve(null)),
    [effectiveId],
  );
  const investigation = useApi(
    () => (effectiveId ? api.getInvestigation(effectiveId) : Promise.resolve(null)),
    [effectiveId],
  );

  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const progressMsg = useProgressMessage(running);

  async function runInvestigation() {
    if (!effectiveId) return;
    setRunning(true);
    setRunError(null);
    try {
      await api.investigate(effectiveId);
      await investigation.refresh();
    } catch (err) {
      setRunError(err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(false);
    }
  }

  async function downloadPdf() {
    if (!effectiveId) return;
    setDownloadingPdf(true);
    setRunError(null);
    try {
      const blob = await api.getReportPdf(effectiveId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `nexus-one-report-${effectiveId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      setRunError(err instanceof Error ? err.message : String(err));
    } finally {
      setDownloadingPdf(false);
    }
  }

  const isDemo =
    investigation.data?.analysis_mode?.toUpperCase().includes('DEMO') ?? false;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">AI Investigator</h1>
          <p className="page-subtitle">
            Select an incident, review its evidence, then run the AI investigation.
            {isDemo ? ' DEMO MODE — deterministic mock provider is active.' : ''}
          </p>
        </div>
        <div className="page-actions">
          {investigation.data ? (
            <span className={`badge ${isDemo ? 'badge-demo' : 'badge-live'}`} data-testid="investigator-mode">
              {isDemo ? 'DEMO MODE' : 'LIVE LLM'}
            </span>
          ) : null}
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
          title="No incidents to investigate"
          hint="Run the attack scenario from the dashboard to create correlated incidents."
        />
      ) : (
        <div className="investigator-grid">
          <section className="panel investigator-list" data-testid="investigator-incident-list">
            <h2 className="panel-title">Incidents</h2>
            {(incidents.data ?? []).map((incident) => (
              <button
                key={incident.id}
                type="button"
                className={`investigator-item${incident.id === effectiveId ? ' selected' : ''}`}
                onClick={() => setSelectedId(incident.id)}
                data-testid="investigator-incident-option"
              >
                <span className="investigator-item-title">{incident.title}</span>
                <span className="investigator-item-meta">
                  <SeverityBadge severity={incident.severity} />
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                    {incident.id.slice(0, 8)}
                  </span>
                </span>
              </button>
            ))}
          </section>

          <div className="investigator-detail">
            {selected ? (
              <>
                <section className="panel" data-testid="investigator-summary">
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: 12,
                      flexWrap: 'wrap',
                      marginBottom: 10,
                    }}
                  >
                    <h2 className="panel-title" style={{ marginBottom: 0 }}>
                      {selected.title}
                    </h2>
                    <Link to={`/incidents/${selected.id}`} className="mono" style={{ fontSize: 12 }}>
                      Open incident →
                    </Link>
                  </div>
                  <div className="meta-line" style={{ marginBottom: 8 }}>
                    <span>
                      <SeverityBadge severity={selected.severity} />
                    </span>
                    <span>
                      <StatusBadge status={selected.status} />
                    </span>
                    {selected.risk_score != null ? (
                      <span
                        className="mono"
                        style={{ color: riskLevelColor(selected.risk_level), fontWeight: 600 }}
                      >
                        RISK {selected.risk_score.toFixed(1)} ({selected.risk_level})
                      </span>
                    ) : null}
                    <span>
                      Alerts: <b className="mono">{selected.alert_count}</b>
                    </span>
                    <span>{formatDateTime(selected.first_seen)} → {formatDateTime(selected.last_seen)}</span>
                  </div>
                  {selected.attack_stages.length > 0 ? (
                    <div className="stage-list" data-testid="investigator-stages">
                      {selected.attack_stages.map((stage) => (
                        <span key={stage} className="badge badge-neutral">
                          {stageLabel(stage)}
                        </span>
                      ))}
                    </div>
                  ) : null}
                </section>

                <div
                  className="investigator-action-bar"
                  data-testid="investigator-action-bar"
                >
                  <button
                    type="button"
                    className="btn btn-primary btn-lg investigator-run-btn"
                    onClick={() => void runInvestigation()}
                    disabled={!effectiveId || running}
                    data-testid="investigate-button-primary"
                  >
                    {running ? (
                      <>
                        <span className="investigator-spinner" aria-hidden="true" />
                        {progressMsg}
                      </>
                    ) : investigation.data ? (
                      <>▶ Re-run AI Investigation</>
                    ) : (
                      <>▶ Run AI Investigation</>
                    )}
                  </button>
                  {isDemo ? (
                    <span className={`badge badge-demo`} data-testid="investigator-mode-inline">
                      DEMO MODE
                    </span>
                  ) : investigation.data ? (
                    <span className="badge badge-live" data-testid="investigator-mode-inline">
                      LIVE LLM
                    </span>
                  ) : null}
                  {investigation.data ? (
                    <>
                      <button
                        type="button"
                        className="btn"
                        onClick={() => void downloadPdf()}
                        disabled={downloadingPdf}
                        data-testid="investigator-download-pdf"
                      >
                        {downloadingPdf ? 'Preparing PDF...' : 'Download PDF'}
                      </button>
                    </>
                  ) : null}
                </div>

                {runError ? (
                  <div className="error-banner" role="alert" data-testid="investigation-error-inline">
                    <span aria-hidden="true">⚠</span>
                    <span>{runError}</span>
                  </div>
                ) : null}

                <section className="panel" data-testid="investigator-evidence">
                  <h2 className="panel-title" style={{ marginBottom: 10 }}>
                    Timeline Evidence
                  </h2>

                  {summary.error ? <ErrorBanner message={summary.error} /> : null}

                  {summary.loading ? (
                    <Loading label="Loading evidence…" />
                  ) : summary.data ? (
                    <div>
                      {summary.data.timeline.entries.length > 0 ? (
                        <div className="table-wrap">
                          <table data-testid="investigator-timeline">
                            <thead>
                              <tr>
                                <th>Time</th>
                                <th>Event</th>
                                <th>Severity</th>
                                <th>Method</th>
                                <th>Description</th>
                                <th>Evidence</th>
                              </tr>
                            </thead>
                            <tbody>
                              {summary.data.timeline.entries.map((entry, i) => (
                                <tr key={i}>
                                  <td className="mono" style={{ color: 'var(--text-muted)' }}>
                                    {formatDateTime(entry.timestamp ?? null)}
                                  </td>
                                  <td className="mono">{entry.event_type ?? '—'}</td>
                                  <td>
                                    <SeverityBadge severity={entry.severity} />
                                  </td>
                                  <td>
                                    <span className="badge badge-neutral">
                                      {entry.detection_method === 'ml' ? 'ML' : 'RULE'}
                                    </span>
                                  </td>
                                  <td style={{ color: 'var(--text-muted)' }}>{entry.description ?? '—'}</td>
                                  <td>
                                    <EvidenceIds
                                      ids={[
                                        ...(entry.alert_id ? [`alert-${entry.alert_id}`] : []),
                                        ...(entry.event_id ? [`event-${entry.event_id}`] : []),
                                      ]}
                                    />
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <EmptyState title="No timeline entries" />
                      )}

                      <div className="meta-line" style={{ marginTop: 12 }}>
                        <span>
                          Users: <b className="mono">{selected.users.join(', ') || '—'}</b>
                        </span>
                        <span>
                          Hosts: <b className="mono">{selected.hosts.join(', ') || '—'}</b>
                        </span>
                        <span>
                          Source IPs: <b className="mono">{selected.source_ips.join(', ') || '—'}</b>
                        </span>
                      </div>
                    </div>
                  ) : (
                    <EmptyState title="Evidence unavailable" />
                  )}
                </section>
              </>
            ) : (
              <section className="panel">
                <EmptyState title="Select an incident" hint="Pick an incident from the list to view evidence." />
              </section>
            )}

            <InvestigationPanel
              investigation={investigation.data}
              running={running}
              error={runError ?? investigation.error}
              onRun={() => void runInvestigation()}
              disabled={!effectiveId}
            />
          </div>
        </div>
      )}
    </div>
  );
}
