import { EmptyState } from '@/components/States';
import { riskLevelColor } from '@/utils/format';
import type { RiskAssessment } from '@/types';

export default function RiskPanel({ risk }: { risk: RiskAssessment | null }) {
  if (!risk) {
    return (
      <section className="panel" data-testid="risk-panel">
        <h2 className="panel-title">Risk Assessment</h2>
        <EmptyState title="No risk assessment available" />
      </section>
    );
  }

  const score = risk.risk_score ?? 0;
  const color = riskLevelColor(risk.risk_level);

  return (
    <section className="panel risk-panel" data-testid="risk-panel">
      <h2 className="panel-title">Risk Assessment</h2>
      <div className="risk-score-row">
        <span className="risk-score-big" style={{ color }} data-testid="risk-score">
          {score.toFixed(1)}
        </span>
        <div style={{ flex: 1 }}>
          <span className="badge badge-neutral" style={{ color, borderColor: color }}>
            {risk.risk_level}
          </span>
          <div className="risk-bar" style={{ marginTop: 10 }}>
            <div
              className="risk-bar-fill"
              style={{ width: `${Math.min(100, Math.max(0, score))}%`, background: color }}
              role="progressbar"
              aria-valuenow={score}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="Risk score"
            />
          </div>
        </div>
      </div>

      {risk.contributing_factors.length > 0 ? (
        <div>
          <h3 className="panel-title" style={{ marginBottom: 8 }}>
            Contributing Factors
          </h3>
          <ul className="factor-list" data-testid="risk-factors">
            {risk.contributing_factors.map((factor) => (
              <li key={factor}>{factor}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {risk.scoring_explanation ? (
        <div>
          <h3 className="panel-title" style={{ marginBottom: 8 }}>
            Scoring Explanation
          </h3>
          <p className="explanation" data-testid="risk-explanation">
            {risk.scoring_explanation}
          </p>
        </div>
      ) : null}
    </section>
  );
}
