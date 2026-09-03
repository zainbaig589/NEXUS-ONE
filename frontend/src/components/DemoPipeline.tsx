/**
 * DemoPipeline — visual progress indicator for the one-click attack scenario.
 * Shows 6 pipeline stages with animated transitions and a result summary panel.
 */

import { useEffect, useState } from 'react';
import type { DemoAttackScenarioResponse } from '@/types';
import { shortId } from '@/utils/format';

const STAGES = ['INGEST', 'DETECT', 'CORRELATE', 'INVESTIGATE', 'RECOMMEND', 'REPORT'] as const;

const STAGE_LABELS: Record<string, string> = {
  INGEST: 'Ingest Events',
  DETECT: 'Run Detection',
  CORRELATE: 'Correlate Alerts',
  INVESTIGATE: 'AI Investigation',
  RECOMMEND: 'Recommendations',
  REPORT: 'Generate Report',
};

interface DemoPipelineProps {
  running: boolean;
  result: DemoAttackScenarioResponse | null;
  onViewIncident: (id: string) => void;
}

function stageStatus(
  stage: string,
  running: boolean,
  result: DemoAttackScenarioResponse | null,
): 'idle' | 'active' | 'success' | 'error' | 'skipped' {
  if (result) {
    const entry = result.stages.find((s) => s.stage === stage);
    if (!entry) return 'idle';
    if (entry.status === 'error') return 'error';
    if (entry.status === 'skipped') return 'skipped';
    return 'success';
  }
  if (!running) return 'idle';
  return 'active';
}

function useProgressiveStage(running: boolean, result: DemoAttackScenarioResponse | null): number {
  const [progressIdx, setProgressIdx] = useState(0);

  useEffect(() => {
    if (!running) {
      setProgressIdx(0);
      return;
    }

    setProgressIdx(0);
    const interval = setInterval(() => {
      setProgressIdx((prev) => {
        if (prev >= STAGES.length - 1) {
          return prev;
        }
        return prev + 1;
      });
    }, 400);

    return () => clearInterval(interval);
  }, [running]);

  if (result) return -1;
  if (!running) return -1;
  return progressIdx;
}

export default function DemoPipeline({ running, result, onViewIncident }: DemoPipelineProps) {
  const activeIdx = useProgressiveStage(running, result);

  return (
    <div className="demo-pipeline-container" data-testid="demo-pipeline">
      <div className="demo-pipeline">
        {STAGES.map((stage, i) => {
          const status = stageStatus(stage, running, result);
          const isActive = running && i === activeIdx;
          const entry = result?.stages.find((s) => s.stage === stage);

          return (
            <div className="demo-pipeline-stage" key={stage}>
              {i > 0 && (
                <div
                  className={`demo-pipeline-connector ${
                    status !== 'idle' && status !== 'active' ? 'done' : ''
                  }`}
                />
              )}
              <div
                className={`demo-pipeline-node ${status} ${isActive ? 'animating' : ''}`}
                style={{ animationDelay: running ? `${i * 200}ms` : undefined }}
              >
                <div className="demo-node-indicator">
                  {status === 'success' && (
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                      <path d="M2.5 6L5 8.5L9.5 3.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  )}
                  {status === 'error' && (
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                      <path d="M3 3L9 9M9 3L3 9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                    </svg>
                  )}
                  {status === 'active' && <span className="demo-node-pulse" />}
                </div>
                <span className="demo-node-label">{STAGE_LABELS[stage]}</span>
                {entry && entry.duration_ms > 0 && (
                  <span className="demo-node-duration">{entry.duration_ms}ms</span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {result && <DemoResultPanel result={result} onViewIncident={onViewIncident} />}
    </div>
  );
}

function DemoResultPanel({
  result,
  onViewIncident,
}: {
  result: DemoAttackScenarioResponse;
  onViewIncident: (id: string) => void;
}) {
  const hasErrors = result.stages.some((s) => s.status === 'error');

  return (
    <div className={`demo-result-panel ${hasErrors ? 'has-errors' : ''}`} data-testid="demo-result">
      <div className="demo-result-header">
        <div>
          <h3 className="demo-result-title">
            {hasErrors ? 'Scenario completed with errors' : 'Attack scenario complete'}
          </h3>
          <p className="demo-result-subtitle">
            Run {shortId(result.demo_run_id)} &middot; {new Date(result.executed_at).toLocaleString()}
            <br />
            Full pipeline executed in {result.total_duration_ms}ms
            {result.primary_incident_id && (
              <> &middot; Incident {shortId(result.primary_incident_id)}</>
            )}
          </p>
        </div>
        {result.primary_incident_id && (
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={() => onViewIncident(result.primary_incident_id!)}
          >
            View Incident
          </button>
        )}
      </div>

      <div className="demo-metric-grid">
        <div className="demo-metric">
          <span className="demo-metric-value">{result.events_created}</span>
          <span className="demo-metric-label">Events Ingested</span>
        </div>
        <div className="demo-metric">
          <span className="demo-metric-value">{result.alerts_created}</span>
          <span className="demo-metric-label">Alerts Generated</span>
        </div>
        <div className="demo-metric">
          <span className="demo-metric-value">{result.rule_detections}</span>
          <span className="demo-metric-label">Rule Detections</span>
        </div>
        <div className="demo-metric">
          <span className="demo-metric-value">{result.ml_detections}</span>
          <span className="demo-metric-label">ML Detections</span>
        </div>
        <div className="demo-metric">
          <span className="demo-metric-value">{result.incidents_created}</span>
          <span className="demo-metric-label">Incidents Created</span>
        </div>
        {result.risk_score != null && (
          <div className="demo-metric">
            <span className="demo-metric-value">{result.risk_score.toFixed(0)}</span>
            <span className="demo-metric-label">Risk Score ({result.risk_level})</span>
          </div>
        )}
        <div className="demo-metric">
          <span className="demo-metric-value">{result.recommendation_count}</span>
          <span className="demo-metric-label">Recommendations</span>
        </div>
        <div className="demo-metric">
          <span className="demo-metric-value">{result.report_generated ? 'Yes' : 'No'}</span>
          <span className="demo-metric-label">Report Generated</span>
        </div>
      </div>

      {result.attack_stages.length > 0 && (
        <div className="demo-attack-stages">
          <span className="demo-stages-label">Attack Stages:</span>
          {result.attack_stages.map((stage) => (
            <span className="demo-stage-badge" key={stage}>
              {stage.replace('Potential stage: ', '')}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
