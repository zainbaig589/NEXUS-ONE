import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '@/api/nexus';
import { useApi } from '@/hooks/useApi';
import SeverityBadge from '@/components/SeverityBadge';
import { EmptyState, ErrorBanner, Loading } from '@/components/States';
import { formatDateTime, severityRank } from '@/utils/format';
import type { Alert, Incident, SecurityEvent } from '@/types';

type IndicatorType = 'IP Address' | 'Domain' | 'Host' | 'User';

interface Indicator {
  value: string;
  type: IndicatorType;
  firstSeen: string;
  lastSeen: string;
  eventCount: number;
  alertCount: number;
  alertIds: string[];
  maxAlertSeverity: string | null;
  incidentCount: number;
  incidentIds: string[];
}

const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

function classify(kind: 'ip' | 'host' | 'user', value: string): IndicatorType {
  if (kind === 'ip') return 'IP Address';
  if (kind === 'user') return 'User';
  return value.includes('.') && !IP_RE.test(value) ? 'Domain' : 'Host';
}

interface IndicatorDraft extends Omit<Indicator, 'alertCount' | 'alertIds' | 'maxAlertSeverity' | 'incidentCount' | 'incidentIds'> {
  alertIds: string[];
  alertSeverities: string[];
}

function collectIndicators(events: SecurityEvent[], alerts: Alert[], incidents: Incident[]): Indicator[] {
  const drafts = new Map<string, IndicatorDraft>();
  const eventIndicators = new Map<string, string[]>();

  const add = (value: unknown, kind: 'ip' | 'host' | 'user', timestamp: string, eventId: string) => {
    if (typeof value !== 'string' || value === '') return;
    let draft = drafts.get(value);
    if (!draft) {
      draft = {
        value,
        type: classify(kind, value),
        firstSeen: timestamp,
        lastSeen: timestamp,
        eventCount: 0,
        alertIds: [],
        alertSeverities: [],
      };
      drafts.set(value, draft);
    }
    draft.eventCount += 1;
    if (new Date(timestamp) < new Date(draft.firstSeen)) draft.firstSeen = timestamp;
    if (new Date(timestamp) > new Date(draft.lastSeen)) draft.lastSeen = timestamp;
    const list = eventIndicators.get(eventId) ?? [];
    if (!list.includes(value)) list.push(value);
    eventIndicators.set(eventId, list);
  };

  for (const event of events) {
    const payload = event.payload ?? {};
    add(payload.src_ip, 'ip', event.timestamp, event.id);
    add(payload.dst_ip, 'ip', event.timestamp, event.id);
    add(payload.host, 'host', event.timestamp, event.id);
    add(payload.user, 'user', event.timestamp, event.id);
  }

  for (const alert of alerts) {
    for (const value of eventIndicators.get(alert.event_id) ?? []) {
      const draft = drafts.get(value);
      if (!draft) continue;
      draft.alertIds.push(alert.id);
      draft.alertSeverities.push(alert.severity);
    }
  }

  for (const incident of incidents) {
    const values = [
      ...incident.source_ips,
      ...incident.destination_ips,
      ...incident.hosts,
      ...incident.users,
    ];
    for (const value of values) {
      const draft = drafts.get(value);
      if (draft) continue;
      // Incidents may reference indicators whose raw events are no longer
      // in the recent-event window; keep them listed with zero event counts.
      drafts.set(value, {
        value,
        type: IP_RE.test(value)
          ? 'IP Address'
          : incident.hosts.includes(value)
            ? 'Host'
            : 'User',
        firstSeen: incident.first_seen ?? incident.created_at,
        lastSeen: incident.last_seen ?? incident.updated_at,
        eventCount: 0,
        alertIds: [],
        alertSeverities: [],
      });
    }
  }

  const incidentIdsByIndicator = new Map<string, string[]>();
  for (const incident of incidents) {
    const values = new Set([
      ...incident.source_ips,
      ...incident.destination_ips,
      ...incident.hosts,
      ...incident.users,
    ]);
    for (const value of values) {
      if (!drafts.has(value)) continue;
      const list = incidentIdsByIndicator.get(value) ?? [];
      list.push(incident.id);
      incidentIdsByIndicator.set(value, list);
    }
  }

  return [...drafts.values()]
    .map((draft) => ({
      value: draft.value,
      type: draft.type,
      firstSeen: draft.firstSeen,
      lastSeen: draft.lastSeen,
      eventCount: draft.eventCount,
      alertCount: new Set(draft.alertIds).size,
      alertIds: [...new Set(draft.alertIds)],
      maxAlertSeverity:
        draft.alertSeverities.sort((a, b) => severityRank(b) - severityRank(a))[0] ?? null,
      incidentCount: (incidentIdsByIndicator.get(draft.value) ?? []).length,
      incidentIds: incidentIdsByIndicator.get(draft.value) ?? [],
    }))
    .sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime());
}

export default function ThreatIntelPage() {
  const [typeFilter, setTypeFilter] = useState('all');

  const incidents = useApi(() => api.listIncidents({ limit: 200 }), [], { pollMs: 30_000 });
  const alerts = useApi(() => api.listAlerts({ limit: 500 }), [], { pollMs: 15_000 });
  const events = useApi(() => api.listEvents({ limit: 500 }), [], { pollMs: 15_000 });

  const indicators = useMemo(
    () => collectIndicators(events.data ?? [], alerts.data ?? [], incidents.data ?? []),
    [events.data, alerts.data, incidents.data],
  );

  const filtered = useMemo(
    () => (typeFilter === 'all' ? indicators : indicators.filter((i) => i.type === typeFilter)),
    [indicators, typeFilter],
  );

  const error = incidents.error ?? alerts.error ?? events.error;
  const loading = incidents.loading || alerts.loading || events.loading;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Indicator Intelligence</h1>
          <p className="page-subtitle">
            Internal Nexus One telemetry — indicators derived from ingested events, detection
            alerts, and correlated incidents.
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

      <div className="meta-line" data-testid="intel-summary" style={{ marginBottom: 16 }}>
        <span>
          Indicators: <b className="mono">{indicators.length}</b>
        </span>
        <span>
          With related alerts: <b className="mono">{indicators.filter((i) => i.alertCount > 0).length}</b>
        </span>
        <span>
          With related incidents:{' '}
          <b className="mono">{indicators.filter((i) => i.incidentCount > 0).length}</b>
        </span>
      </div>

      <div className="filters" style={{ marginBottom: 16 }}>
        <label>
          Type
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            data-testid="intel-type-filter"
          >
            <option value="all">All</option>
            <option value="IP Address">IP Address</option>
            <option value="Domain">Domain</option>
            <option value="Host">Host</option>
            <option value="User">User</option>
          </select>
        </label>
      </div>

      {error ? <ErrorBanner message={error} /> : null}

      {loading ? (
        <Loading label="Loading indicators…" />
      ) : (
        <section className="panel" data-testid="intel-table">
          {filtered.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Indicator</th>
                    <th>Type</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                    <th>Related Alerts</th>
                    <th>Related Incidents</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((indicator) => (
                    <tr key={`${indicator.type}:${indicator.value}`} data-testid="intel-row">
                      <td className="mono">{indicator.value}</td>
                      <td>
                        <span className="badge badge-neutral">{indicator.type}</span>
                      </td>
                      <td style={{ color: 'var(--text-muted)' }}>
                        {formatDateTime(indicator.firstSeen)}
                      </td>
                      <td style={{ color: 'var(--text-muted)' }}>
                        {formatDateTime(indicator.lastSeen)}
                      </td>
                      <td>
                        {indicator.alertCount > 0 ? (
                          <span className="intel-alerts">
                            <b className="mono">{indicator.alertCount}</b>
                            {indicator.maxAlertSeverity ? (
                              <SeverityBadge severity={indicator.maxAlertSeverity} />
                            ) : null}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-dim)' }}>0</span>
                        )}
                      </td>
                      <td>
                        {indicator.incidentCount > 0 ? (
                          <span className="intel-incidents">
                            {indicator.incidentIds.map((id) => (
                              <Link key={id} to={`/incidents/${id}`} className="mono">
                                {id.slice(0, 8)}
                              </Link>
                            ))}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-dim)' }}>0</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : indicators.length === 0 ? (
            <EmptyState
              title="No indicators observed yet"
              hint="Ingest events through the API to populate indicator intelligence."
            />
          ) : (
            <EmptyState title="No indicators match the current filter" />
          )}
        </section>
      )}
    </div>
  );
}
