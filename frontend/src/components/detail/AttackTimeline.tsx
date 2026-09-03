import { EmptyState } from '@/components/States';
import SeverityBadge from '@/components/SeverityBadge';
import { formatDateTime, stageLabel } from '@/utils/format';
import type { Timeline } from '@/types';

export default function AttackTimeline({ timeline }: { timeline: Timeline | null }) {
  if (!timeline) {
    return (
      <section className="panel" data-testid="timeline-panel">
        <h2 className="panel-title">Attack Timeline</h2>
        <EmptyState title="No timeline available" />
      </section>
    );
  }

  const entries = timeline.entries ?? [];

  return (
    <section className="panel" data-testid="timeline-panel">
      <h2 className="panel-title">
        Attack Timeline
        <span style={{ textTransform: 'none', letterSpacing: 0, fontWeight: 400 }}>
          {' '}
          — {entries.length} event{entries.length === 1 ? '' : 's'}
          {timeline.duration_seconds > 0
            ? ` over ${Math.round(timeline.duration_seconds / 60)} min`
            : ''}
        </span>
      </h2>
      {entries.length === 0 ? (
        <EmptyState title="No timeline events recorded" />
      ) : (
        <ol className="timeline" data-testid="timeline-entries">
          {entries.map((entry, index) => (
            <li
              className="timeline-entry"
              key={`${entry.alert_id ?? entry.event_id ?? 'entry'}-${index}`}
            >
              <span
                className="timeline-dot"
                style={{
                  background:
                    entry.severity === 'critical'
                      ? 'var(--critical)'
                      : entry.severity === 'high'
                        ? 'var(--high)'
                        : entry.severity === 'medium'
                          ? 'var(--medium)'
                          : 'var(--low)',
                }}
              />
              <div className="timeline-head">
                <span className="timeline-time">{formatDateTime(entry.timestamp)}</span>
                <SeverityBadge severity={entry.severity} />
                <span style={{ fontWeight: 600 }}>{entry.event_type ?? 'Unknown event'}</span>
                {entry.detection_method === 'ml' ? (
                  <span className="badge badge-demo">ML</span>
                ) : null}
                {entry.stage ? (
                  <span className="badge badge-neutral">{stageLabel(entry.stage)}</span>
                ) : null}
              </div>
              {entry.description ? (
                <div className="timeline-body">
                  <div>{entry.description}</div>
                </div>
              ) : null}
              <div className="timeline-meta">
                {entry.user ? <span>user: {entry.user}</span> : null}
                {entry.host ? <span>host: {entry.host}</span> : null}
                {entry.source_ip ? <span>src: {entry.source_ip}</span> : null}
                {entry.destination_ip ? <span>dst: {entry.destination_ip}</span> : null}
                {entry.detection_method ? <span>via: {entry.detection_method}</span> : null}
              </div>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
