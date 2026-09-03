import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '@/api/nexus';
import { useApi } from '@/hooks/useApi';
import SeverityBadge from '@/components/SeverityBadge';
import StatusBadge from '@/components/StatusBadge';
import { EmptyState, ErrorBanner, Loading } from '@/components/States';
import { formatDateTime, riskLevelColor, severityRank } from '@/utils/format';
import type { Incident } from '@/types';

type SortKey = 'title' | 'severity' | 'risk' | 'status' | 'first_seen' | 'last_seen' | 'alerts';

const SORTABLE_COLUMNS: Array<{ key: SortKey; label: string }> = [
  { key: 'title', label: 'Title' },
  { key: 'severity', label: 'Severity' },
  { key: 'risk', label: 'Risk' },
  { key: 'status', label: 'Status' },
  { key: 'first_seen', label: 'First Seen' },
  { key: 'last_seen', label: 'Last Seen' },
  { key: 'alerts', label: 'Alerts' },
];

export default function IncidentsPage() {
  const navigate = useNavigate();
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [sortKey, setSortKey] = useState<SortKey>('last_seen');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [refreshNonce, setRefreshNonce] = useState(0);

  const incidents = useApi(
    () => api.listIncidents(statusFilter ? { status: statusFilter, limit: 200 } : { limit: 200 }),
    [statusFilter],
    { pollMs: 30_000 },
  );

  const incidentIds = useMemo(() => (incidents.data ?? []).map((i) => i.id), [incidents.data]);
  const detectionKey = `${incidentIds.join(',')}#${refreshNonce}`;
  const [detectionMap, setDetectionMap] = useState<Record<string, string[]>>({});

  useEffect(() => {
    let cancelled = false;
    if (incidentIds.length === 0) {
      setDetectionMap({});
      return () => {
        cancelled = true;
      };
    }
    void (async () => {
      const entries = await Promise.all(
        incidentIds.map(async (id) => {
          try {
            const alerts = await api.getIncidentAlerts(id);
            const methods = [...new Set(alerts.map((a) => (a.detection_source === 'ml' ? 'ML' : 'Rule')))];
            return [id, methods] as const;
          } catch {
            return [id, []] as const;
          }
        }),
      );
      if (!cancelled) setDetectionMap(Object.fromEntries(entries));
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detectionKey]);

  const filtered = useMemo(() => {
    let rows = incidents.data ?? [];
    if (severityFilter !== 'all') {
      rows = rows.filter((i) => i.severity?.toLowerCase() === severityFilter);
    }
    const dir = sortDir === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      switch (sortKey) {
        case 'title':
          return a.title.localeCompare(b.title) * dir;
        case 'severity':
          return (severityRank(a.severity) - severityRank(b.severity)) * dir;
        case 'risk':
          return ((a.risk_score ?? -1) - (b.risk_score ?? -1)) * dir;
        case 'status':
          return (a.status ?? '').localeCompare(b.status ?? '') * dir;
        case 'alerts':
          return (a.alert_count - b.alert_count) * dir;
        case 'first_seen':
          return (
            (new Date(a.first_seen ?? 0).getTime() - new Date(b.first_seen ?? 0).getTime()) * dir
          );
        case 'last_seen':
          return (new Date(a.last_seen ?? 0).getTime() - new Date(b.last_seen ?? 0).getTime()) * dir;
        default:
          return 0;
      }
    });
  }, [incidents.data, severityFilter, sortKey, sortDir]);

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Incidents</h1>
          <p className="page-subtitle">
            {filtered.length} of {incidents.data?.length ?? 0} incidents
            {incidents.lastUpdated ? ` — updated ${formatDateTime(incidents.lastUpdated)}` : ''}
          </p>
        </div>
        <div className="page-actions">
          <button
            type="button"
            className="btn"
            onClick={() => {
              setRefreshNonce((n) => n + 1);
              void incidents.refresh();
            }}
            disabled={incidents.refreshing}
          >
            {incidents.refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      <div className="filters" style={{ marginBottom: 16 }}>
        <label>
          Severity
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            data-testid="severity-filter"
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
            data-testid="status-filter"
          >
            <option value="">All</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="closed">Closed</option>
          </select>
        </label>
      </div>

      {incidents.error ? <ErrorBanner message={incidents.error} onRetry={incidents.refresh} /> : null}

      {incidents.loading ? (
        <Loading label="Loading incidents…" />
      ) : (
        <section className="panel" data-testid="incidents-table">
          {filtered.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Incident ID</th>
                    {SORTABLE_COLUMNS.map((col) => (
                      <th
                        key={col.key}
                        className="sortable"
                        onClick={() => toggleSort(col.key)}
                        aria-sort={
                          sortKey === col.key ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'
                        }
                      >
                        {col.label}
                        {sortKey === col.key ? (sortDir === 'asc' ? ' ▲' : ' ▼') : ''}
                      </th>
                    ))}
                    <th>Detection Methods</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((incident) => (
                    <IncidentRow
                      key={incident.id}
                      incident={incident}
                      detectionMethods={detectionMap[incident.id] ?? []}
                      onOpen={() => navigate(`/incidents/${incident.id}`)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          ) : (incidents.data?.length ?? 0) === 0 ? (
            <EmptyState
              title="No incidents found"
              hint="Run the attack scenario from the dashboard to create correlated incidents."
            />
          ) : (
            <EmptyState title="No incidents match the current filters" />
          )}
        </section>
      )}
    </div>
  );
}

function IncidentRow({
  incident,
  detectionMethods,
  onOpen,
}: {
  incident: Incident;
  detectionMethods: string[];
  onOpen: () => void;
}) {
  return (
    <tr className="clickable" onClick={onOpen} data-testid="incident-row">
      <td>
        <Link
          to={`/incidents/${incident.id}`}
          className="mono"
          onClick={(e) => e.stopPropagation()}
        >
          {incident.id.slice(0, 8)}
        </Link>
      </td>
      <td>{incident.title}</td>
      <td>
        <SeverityBadge severity={incident.severity} />
      </td>
      <td>
        {incident.risk_score != null ? (
          <span
            className="mono"
            style={{ color: riskLevelColor(incident.risk_level), fontWeight: 600 }}
          >
            {incident.risk_score.toFixed(1)}
          </span>
        ) : (
          <span style={{ color: 'var(--text-dim)' }}>—</span>
        )}
      </td>
      <td>
        <StatusBadge status={incident.status} />
      </td>
      <td style={{ color: 'var(--text-muted)' }}>{formatDateTime(incident.first_seen)}</td>
      <td style={{ color: 'var(--text-muted)' }}>{formatDateTime(incident.last_seen)}</td>
      <td className="num">{incident.alert_count}</td>
      <td>
        {detectionMethods.length > 0 ? (
          <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>
            {detectionMethods.join(' + ')}
          </span>
        ) : (
          <span style={{ color: 'var(--text-dim)' }}>—</span>
        )}
      </td>
    </tr>
  );
}
