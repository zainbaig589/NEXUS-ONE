import { EmptyState } from '@/components/States';
import { stageLabel } from '@/utils/format';

export default function AttackStages({ stages }: { stages: string[] }) {
  return (
    <section className="panel" data-testid="stages-panel">
      <h2 className="panel-title">Attack Stages</h2>
      {stages.length === 0 ? (
        <EmptyState title="No attack stages classified" />
      ) : (
        <div className="stage-list" data-testid="stage-list">
          {stages.map((stage, index) => (
            <div className="stage-item" key={stage}>
              <span className="stage-num">{String(index + 1).padStart(2, '0')}</span>
              <span>{stageLabel(stage)}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
