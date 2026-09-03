import { useMemo, useState } from 'react';
import { api } from '@/api/nexus';
import { useApi } from '@/hooks/useApi';
import SeverityBadge from '@/components/SeverityBadge';
import StatusBadge from '@/components/StatusBadge';
import { EmptyState, ErrorBanner, Loading } from '@/components/States';
import { formatDateTime, shortId, SEVERITY_ORDER } from '@/utils/format';
import type { Alert } from '@/types';

export default function AlertsPage() {
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('');

  const alerts = useApi(
    () =>
      api.listAlerts({
        severity: severityFilter !== 'all' ? severityFilter : undefined,
        status: statusFilter || undefined,
        limit: 500,
      }),
    [severityFilter, statusFilter],
    { pollMs: 15_000 },
  );

  const sorted = useMemo(() => {
    const rows = alerts.data ?? [];
    return [...rows].sort(
      (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
    );
  }, [alerts.data]);

  const bySeverity = useMemo(() => {
    const counts = new Map<string, number>();
    for (const alert of alerts.data ?? []) {
      const sev = (alert.severity ?? 'info').toLowerCase();
      counts.set(sev, (counts.get(sev) ?? 0) + 1);
    }
    return counts;
  }, [alerts.data]);

  const mlCount = useMemo(
    () => (alerts.data ?? []).filter((a) => a.detection_source === 'ml').length,
    [alerts.data],
  );

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Alerts</h1>
          <p className="page-subtitle">
            {sorted.length} of {alerts.data?.length ?? 0} detection alerts
            {alerts.lastUpdated ? ` — updated ${formatDateTime(alerts.lastUpdated)}` : ''}
          </p>
        </div>
        <div className="page-actions">
          <button
            type="button"
            className="btn"
            onClick={() => void alerts.refresh()}
            disabled={alerts.refreshing}
          >
            {alerts.refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      <div className="meta-line" data-testid="alerts-summary" style={{ marginBottom: 16 }}>
        <span>
          Rule engine: <b className="mono">{(alerts.data?.length ?? 0) - mlCount}</b>
        </span>
        <span>
          ML anomalies: <b className="mono">{mlCount}</b>
        </span>
        {SEVERITY_ORDER.filter((sev) => bySeverity.get(sev)).map((sev) => (
          <span key={sev}>
            {sev}: <b className="mono">{bySeverity.get(sev)}</b>
          </span>
        ))}
      </div>

      <div className="filters" style={{ marginBottom: 16 }}>
        <label>
          Severity
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            data-testid="alerts-severity-filter"
          >
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </label>
        <label>
          Status
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            data-testid="alerts-status-filter"
          >
            <option value="">All</option>
            <option value="new">New</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
          </select>
        </label>
      </div>

      {alerts.error ? <ErrorBanner message={alerts.error} onRetry={alerts.refresh} /> : null}

      {alerts.loading ? (
        <Loading label="Loading alerts…" />
      ) : (
        <section className="panel" data-testid="alerts-table">
          {sorted.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Alert ID</th>
                    <th>Rule</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Source</th>
                    <th>Description</th>
                    <th>Event</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((alert) => (
                    <AlertRow key={alert.id} alert={alert} />
                  ))}
                </tbody>
              </table>
            </div>
          ) : (alerts.data?.length ?? 0) === 0 ? (
            <EmptyState
              title="No alerts found"
              hint="Ingest events and run detection to produce alerts."
            />
          ) : (
            <EmptyState title="No alerts match the current filters" />
          )}
        </section>
      )}
    </div>
  );
}

function AlertRow({ alert }: { alert: Alert }) {
  return (
    <tr data-testid="alert-row">
      <td className="mono">{shortId(alert.id, 10)}</td>
      <td>{alert.rule_name}</td>
      <td>
        <SeverityBadge severity={alert.severity} />
      </td>
      <td>
        <StatusBadge status={alert.status} />
      </td>
      <td>
        <span
          className={`badge ${alert.detection_source === 'ml' ? 'badge-info' : 'badge-neutral'}`}
        >
          {alert.detection_source === 'ml' ? 'ML' : 'RULE'}
        </span>
      </td>
      <td style={{ color: 'var(--text-muted)' }}>{alert.description ?? '—'}</td>
      <td className="mono" style={{ color: 'var(--text-muted)' }}>
        {shortId(alert.event_id, 8)}
      </td>
      <td style={{ color: 'var(--text-muted)' }}>{formatDateTime(alert.created_at)}</td>
    </tr>
  );
}
