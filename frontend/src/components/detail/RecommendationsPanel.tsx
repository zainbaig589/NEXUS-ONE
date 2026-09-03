import EvidenceIds from '@/components/EvidenceIds';
import { EmptyState, ErrorBanner, Loading } from '@/components/States';
import { formatConfidence } from '@/utils/format';
import type { RecommendationsResponse } from '@/types';

const PRIORITY_CLASS: Record<string, string> = {
  CRITICAL: 'badge-critical',
  HIGH: 'badge-high',
  MEDIUM: 'badge-medium',
  LOW: 'badge-low',
};

export default function RecommendationsPanel({
  recommendations,
  loading,
  error,
  onRetry,
}: {
  recommendations: RecommendationsResponse | null;
  loading: boolean;
  error: string | null;
  onRetry?: () => void;
}) {
  return (
    <section className="panel" data-testid="recommendations-panel">
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
          Response Recommendations
        </h2>
        <span className="badge badge-advisory">ADVISORY — REQUIRES ANALYST APPROVAL</span>
      </div>

      {error ? <ErrorBanner message={error} onRetry={onRetry} /> : null}

      {loading ? (
        <Loading label="Generating recommendations…" />
      ) : !recommendations || recommendations.recommendations.length === 0 ? (
        <EmptyState title="No recommendations available" />
      ) : (
        <div data-testid="recommendations-list">
          {recommendations.recommendations.map((reco) => (
            <div className="reco-card" key={reco.recommendation_id} data-testid="recommendation-card">
              <div className="reco-head">
                <span className={`badge ${PRIORITY_CLASS[reco.priority] ?? 'badge-neutral'}`}>
                  {reco.priority}
                </span>
                <span className="reco-title">{reco.title}</span>
                <span className="badge badge-neutral">{reco.category}</span>
              </div>
              <div className="reco-meta">
                <span>Priority score: {reco.priority_score.toFixed(0)}/100</span>
                <span>Confidence: {formatConfidence(reco.confidence)}</span>
                {reco.requires_analyst_approval ? (
                  <span className="badge badge-advisory">approval required</span>
                ) : null}
              </div>
              <p className="reco-body">{reco.description}</p>
              <p className="reco-body" style={{ marginTop: 8 }}>
                <strong style={{ color: 'var(--text)' }}>Rationale:</strong> {reco.rationale}
              </p>
              <div style={{ marginTop: 10 }}>
                <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>Evidence: </span>
                <EvidenceIds ids={reco.evidence_ids} emptyLabel="none cited" />
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
