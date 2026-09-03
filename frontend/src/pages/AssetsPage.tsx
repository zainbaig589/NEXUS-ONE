import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '@/api/nexus';
import { useApi } from '@/hooks/useApi';
import { EmptyState, ErrorBanner, Loading } from '@/components/States';
import { formatDateTime } from '@/utils/format';
import type { Alert, Incident, SecurityEvent } from '@/types';

type AssetType = 'Host' | 'User' | 'Source IP' | 'Destination IP' | 'Endpoint';

interface Asset {
  value: string;
  type: AssetType;
  eventCount: number;
  alertCount: number;
  incidentCount: number;
  incidentIds: string[];
  lastObserved: string;
}

export default function AssetsPage() {
  const [typeFilter, setTypeFilter] = useState('all');

  const incidents = useApi(() => api.listIncidents({ limit: 200 }), [], { pollMs: 30_000 });
  const alerts = useApi(() => api.listAlerts({ limit: 500 }), [], { pollMs: 15_000 });
  const events = useApi(() => api.listEvents({ limit: 500 }), [], { pollMs: 15_000 });

  const assets = useMemo(
    () => buildAssets(events.data ?? [], alerts.data ?? [], incidents.data ?? []),
    [events.data, alerts.data, incidents.data],
  );

  const filtered = useMemo(
    () => (typeFilter === 'all' ? assets : assets.filter((a) => a.type === typeFilter)),
    [assets, typeFilter],
  );

  const error = incidents.error ?? alerts.error ?? events.error;
  const loading = incidents.loading || alerts.loading || events.loading;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Observed Assets</h1>
          <p className="page-subtitle">
            Assets discovered in actual Nexus One telemetry — hosts, users, IP addresses, and
            event-source endpoints observed in ingested events.
          </p>
        </div>
        <div className="page-actions">
          <button
            type="button"
            className="btn"
            onClick={() => {
              void incidents.refresh();
              void alerts.refresh();
              void events.refresh();
            }}
            disabled={incidents.refreshing || alerts.refreshing || events.refreshing}
          >
            {incidents.refreshing || alerts.refreshing || events.refreshing
              ? 'Refreshing…'
              : 'Refresh'}
          </button>
        </div>
      </div>

      <div className="meta-line" data-testid="assets-summary" style={{ marginBottom: 16 }}>
        <span>
          Assets: <b className="mono">{assets.length}</b>
        </span>
        <span>
          Hosts: <b className="mono">{assets.filter((a) => a.type === 'Host').length}</b>
        </span>
        <span>
          Users: <b className="mono">{assets.filter((a) => a.type === 'User').length}</b>
        </span>
        <span>
          IPs: <b className="mono">{assets.filter((a) => a.type.endsWith('IP')).length}</b>
        </span>
        <span>
          Endpoints: <b className="mono">{assets.filter((a) => a.type === 'Endpoint').length}</b>
        </span>
      </div>

      <div className="filters" style={{ marginBottom: 16 }}>
        <label>
          Type
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            data-testid="assets-type-filter"
          >
            <option value="all">All</option>
            <option value="Host">Host</option>
            <option value="User">User</option>
            <option value="Source IP">Source IP</option>
            <option value="Destination IP">Destination IP</option>
            <option value="Endpoint">Endpoint</option>
          </select>
        </label>
      </div>

      {error ? <ErrorBanner message={error} /> : null}

      {loading ? (
        <Loading label="Loading assets…" />
      ) : (
        <section className="panel" data-testid="assets-table">
          {filtered.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th>Type</th>
                    <th>Event Count</th>
                    <th>Alert Count</th>
                    <th>Incident Count</th>
                    <th>Last Observed</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((asset) => (
                    <tr key={`${asset.type}:${asset.value}`} data-testid="asset-row">
                      <td className="mono">{asset.value}</td>
                      <td>
                        <span className="badge badge-neutral">{asset.type}</span>
                      </td>
                      <td className="num">{asset.eventCount}</td>
                      <td className="num">{asset.alertCount}</td>
                      <td>
                        {asset.incidentCount > 0 ? (
                          <span className="asset-incidents">
                            <b className="mono">{asset.incidentCount}</b>
                            {asset.incidentIds.slice(0, 3).map((id) => (
                              <Link key={id} to={`/incidents/${id}`} className="mono">
                                {id.slice(0, 8)}
                              </Link>
                            ))}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-dim)' }}>0</span>
                        )}
                      </td>
                      <td style={{ color: 'var(--text-muted)' }}>
                        {formatDateTime(asset.lastObserved)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : assets.length === 0 ? (
            <EmptyState
              title="No assets observed yet"
              hint="Ingest events through the API to discover assets."
            />
          ) : (
            <EmptyState title="No assets match the current filter" />
          )}
        </section>
      )}
    </div>
  );
}

function buildAssets(events: SecurityEvent[], alerts: Alert[], incidents: Incident[]): Asset[] {
  const assets = new Map<string, Asset>();
  const eventAssets = new Map<string, string[]>();

  const touch = (value: unknown, type: AssetType, timestamp: string, eventId: string) => {
    if (typeof value !== 'string' || value === '') return;
    const key = `${type}:${value}`;
    let asset = assets.get(key);
    if (!asset) {
      asset = {
        value,
        type,
        eventCount: 0,
        alertCount: 0,
        incidentCount: 0,
        incidentIds: [],
        lastObserved: timestamp,
      };
      assets.set(key, asset);
    }
    asset.eventCount += 1;
    if (new Date(timestamp) > new Date(asset.lastObserved)) asset.lastObserved = timestamp;
    const list = eventAssets.get(eventId) ?? [];
    if (!list.includes(key)) list.push(key);
    eventAssets.set(eventId, list);
  };

  for (const event of events) {
    const payload = event.payload ?? {};
    touch(payload.host, 'Host', event.timestamp, event.id);
    touch(payload.user, 'User', event.timestamp, event.id);
    touch(payload.src_ip, 'Source IP', event.timestamp, event.id);
    touch(payload.dst_ip, 'Destination IP', event.timestamp, event.id);
    touch(event.source, 'Endpoint', event.timestamp, event.id);
  }

  const alertCountByEvent = new Map<string, number>();
  for (const alert of alerts) {
    alertCountByEvent.set(alert.event_id, (alertCountByEvent.get(alert.event_id) ?? 0) + 1);
  }
  for (const [eventId, keys] of eventAssets) {
    const count = alertCountByEvent.get(eventId) ?? 0;
    if (count === 0) continue;
    for (const key of keys) {
      const asset = assets.get(key);
      if (asset) asset.alertCount += count;
    }
  }

  const incidentLinks: Array<{ value: string; type: AssetType; incidentId: string }> = [];
  for (const incident of incidents) {
    const addLink = (values: string[], type: AssetType) => {
      for (const value of values) {
        const key = `${type}:${value}`;
        if (assets.has(key)) incidentLinks.push({ value: key, type, incidentId: incident.id });
      }
    };
    addLink(incident.hosts, 'Host');
    addLink(incident.users, 'User');
    addLink(incident.source_ips, 'Source IP');
    addLink(incident.destination_ips, 'Destination IP');
  }
  for (const link of incidentLinks) {
    const asset = assets.get(link.value);
    if (!asset) continue;
    if (!asset.incidentIds.includes(link.incidentId)) asset.incidentIds.push(link.incidentId);
  }
  for (const asset of assets.values()) {
    asset.incidentCount = asset.incidentIds.length;
  }

  return [...assets.values()].sort((a, b) => {
    if (b.incidentCount !== a.incidentCount) return b.incidentCount - a.incidentCount;
    return new Date(b.lastObserved).getTime() - new Date(a.lastObserved).getTime();
  });
}
