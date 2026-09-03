import { EmptyState } from '@/components/States';
import EvidenceIds from '@/components/EvidenceIds';
import SeverityBadge from '@/components/SeverityBadge';
import { formatDateTime } from '@/utils/format';
import type { Alert } from '@/types';

export default function AlertsEvidenceTable({ alerts }: { alerts: Alert[] }) {
  return (
    <section className="panel" data-testid="alerts-panel">
      <h2 className="panel-title">
        Alerts &amp; Evidence
        <span style={{ textTransform: 'none', letterSpacing: 0, fontWeight: 400 }}>
          {' '}
          — {alerts.length} correlated alert{alerts.length === 1 ? '' : 's'}
        </span>
      </h2>
      {alerts.length === 0 ? (
        <EmptyState title="No alerts correlated to this incident" />
      ) : (
        <div className="table-wrap">
          <table data-testid="alerts-table">
            <thead>
              <tr>
                <th>Alert ID</th>
                <th>Timestamp</th>
                <th>Severity</th>
                <th>Method</th>
                <th>Rule / Model</th>
                <th>Reason</th>
                <th>Related Event</th>
                <th>Evidence IDs</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr key={alert.id}>
                  <td className="mono" title={alert.id}>
                    {alert.id.slice(0, 8)}
                  </td>
                  <td style={{ color: 'var(--text-muted)' }}>{formatDateTime(alert.created_at)}</td>
                  <td>
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td>
                    <span
                      className={`badge ${alert.detection_source === 'ml' ? 'badge-demo' : 'badge-neutral'}`}
                    >
                      {alert.detection_source === 'ml' ? 'ML' : 'Rule'}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-muted)' }}>{alert.rule_name}</td>
                  <td style={{ color: 'var(--text-muted)', maxWidth: 300 }}>{alert.description}</td>
                  <td className="mono" title={alert.event_id}>
                    {alert.event_id ? alert.event_id.slice(0, 8) : '—'}
                  </td>
                  <td>
                    <EvidenceIds
                      ids={[`alert-${alert.id}`, ...(alert.event_id ? [`event-${alert.event_id}`] : [])]}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
