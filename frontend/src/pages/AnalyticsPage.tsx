/**
 * ANALYTICS — every figure derives from real API data: incidents, alerts,
 * raw events, and the ML model status. No fabricated trends.
 */
import { useMemo } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { api } from '@/api/nexus';
import { useApi } from '@/hooks/useApi';
import { EmptyState, ErrorBanner, Loading } from '@/components/States';
import { normalizeSeverity, SEVERITY_ORDER, stageLabel } from '@/utils/format';

const SEVERITY_CHART_COLORS: Record<string, string> = {
  critical: '#f43f5e',
  high: '#f97316',
  medium: '#eab308',
  low: '#38bdf8',
  info: '#64748b',
};

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#f43f5e',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#38bdf8',
};

const TOOLTIP_STYLE = {
  backgroundColor: '#0b1220',
  border: '1px solid rgba(34, 211, 238, 0.25)',
  borderRadius: 6,
  fontSize: 12,
  color: '#e2e8f0',
  boxShadow: '0 6px 24px rgba(2, 6, 14, 0.6)',
};

export default function AnalyticsPage() {
  const incidents = useApi(() => api.listIncidents({ limit: 200 }), [], { pollMs: 30_000 });
  const alerts = useApi(() => api.listAlerts({ limit: 500 }), [], { pollMs: 30_000 });
  const events = useApi(() => api.listEvents({ limit: 500 }), [], { pollMs: 30_000 });
  const mlStatus = useApi(() => api.mlStatus(), [], { pollMs: 60_000 });

  const incidentList = incidents.data ?? [];
  const alertList = alerts.data ?? [];
  const eventList = events.data ?? [];

  const severityData = useMemo(
    () =>
      SEVERITY_ORDER.map((severity) => ({
        name: severity.toUpperCase(),
        key: severity,
        value: incidentList.filter((i) => normalizeSeverity(i.severity) === severity).length,
      })),
    [incidentList],
  );

  const alertSeverityData = useMemo(
    () =>
      SEVERITY_ORDER.map((severity) => ({
        name: severity.toUpperCase(),
        key: severity,
        value: alertList.filter((a) => normalizeSeverity(a.severity) === severity).length,
      })),
    [alertList],
  );

  const detectionData = useMemo(() => {
    const rule = alertList.filter((a) => a.detection_source === 'rule').length;
    const ml = alertList.filter((a) => a.detection_source === 'ml').length;
    return [
      { name: 'RULE', value: rule, color: '#38bdf8' },
      { name: 'ML', value: ml, color: '#a78bfa' },
    ];
  }, [alertList]);

  const riskData = useMemo(() => {
    const levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
    return levels.map((level) => ({
      name: level,
      value: incidentList.filter((i) => (i.risk_level ?? '').toUpperCase() === level).length,
    }));
  }, [incidentList]);

  const attackStages = useMemo(() => {
    const counts = new Map<string, number>();
    for (const incident of incidentList) {
      for (const stage of incident.attack_stages ?? []) {
        const label = stageLabel(stage);
        counts.set(label, (counts.get(label) ?? 0) + 1);
      }
    }
    const max = Math.max(...counts.values(), 1);
    return [...counts.entries()]
      .map(([name, count]) => ({ name, count, width: Math.round((count / max) * 100) }))
      .sort((a, b) => b.count - a.count);
  }, [incidentList]);

  const attackTypes = useMemo(() => {
    const counts = new Map<string, number>();
    for (const event of eventList) {
      const name = event.event_type || 'unknown';
      counts.set(name, (counts.get(name) ?? 0) + 1);
    }
    const max = Math.max(...counts.values(), 1);
    return [...counts.entries()]
      .map(([name, count]) => ({
        name,
        count,
        share: Math.round((count / Math.max(eventList.length, 1)) * 100),
        width: Math.round((count / max) * 100),
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [eventList]);

  const mlAlerts = useMemo(
    () => alertList.filter((a) => a.detection_source === 'ml'),
    [alertList],
  );

  const error = incidents.error ?? alerts.error ?? events.error ?? mlStatus.error;
  const loading = incidents.loading && alerts.loading && events.loading;

  return (
    <div className="page-analytics">
      <div className="page-header">
        <div>
          <h1 className="page-title">Analytics</h1>
          <p className="page-subtitle">
            Operational analytics computed from live Nexus One data
            {incidents.lastUpdated ? ` — updated ${incidents.lastUpdated.toLocaleString()}` : ''}
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
              void mlStatus.refresh();
            }}
            disabled={incidents.refreshing || alerts.refreshing}
          >
            {incidents.refreshing || alerts.refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      {error ? <ErrorBanner message={error} /> : null}

      {loading ? (
        <Loading label="Loading analytics…" />
      ) : (
        <>
          <div className="grid analytics-grid">
            <section className="panel" data-testid="analytics-incident-severity">
              <div className="panel-head">
                <h2 className="panel-title">Incident Severity</h2>
                <span className="panel-tag">{incidentList.length} incidents</span>
              </div>
              {incidentList.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={severityData} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                    <CartesianGrid stroke="rgba(34, 211, 238, 0.08)" vertical={false} />
                    <XAxis
                      dataKey="name"
                      stroke="#64748b"
                      fontSize={10}
                      tickLine={false}
                      axisLine={{ stroke: '#22304d' }}
                    />
                    <YAxis
                      stroke="#64748b"
                      fontSize={10}
                      allowDecimals={false}
                      tickLine={false}
                      axisLine={false}
                      width={36}
                    />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Bar dataKey="value" name="Incidents" radius={[4, 4, 0, 0]}>
                      {severityData.map((entry) => (
                        <Cell key={entry.key} fill={SEVERITY_CHART_COLORS[entry.key]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState
                  title="No incidents yet"
                  hint="Run the attack scenario from the dashboard."
                />
              )}
            </section>

            <section className="panel" data-testid="analytics-alert-distribution">
              <div className="panel-head">
                <h2 className="panel-title">Alert Distribution</h2>
                <span className="panel-tag">{alertList.length} alerts by severity</span>
              </div>
              {alertList.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart
                    data={alertSeverityData}
                    margin={{ top: 8, right: 8, left: -18, bottom: 0 }}
                  >
                    <CartesianGrid stroke="rgba(34, 211, 238, 0.08)" vertical={false} />
                    <XAxis
                      dataKey="name"
                      stroke="#64748b"
                      fontSize={10}
                      tickLine={false}
                      axisLine={{ stroke: '#22304d' }}
                    />
                    <YAxis
                      stroke="#64748b"
                      fontSize={10}
                      allowDecimals={false}
                      tickLine={false}
                      axisLine={false}
                      width={36}
                    />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Bar dataKey="value" name="Alerts" radius={[4, 4, 0, 0]}>
                      {alertSeverityData.map((entry) => (
                        <Cell key={entry.key} fill={SEVERITY_CHART_COLORS[entry.key]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState title="No alerts yet" hint="Ingest events and run detection." />
              )}
            </section>
          </div>

          <div className="grid analytics-grid">
            <section className="panel" data-testid="analytics-detection-methods">
              <div className="panel-head">
                <h2 className="panel-title">Detection Methods</h2>
                <span className="panel-tag">{alertList.length} alerts</span>
              </div>
              {alertList.length > 0 ? (
                <div className="donut-row">
                  <div className="donut-wrap donut-fixed">
                    <ResponsiveContainer width={190} height={190}>
                      <PieChart>
                        <Pie
                          data={detectionData}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          innerRadius={62}
                          outerRadius={88}
                          paddingAngle={3}
                          cornerRadius={5}
                          stroke="none"
                          startAngle={90}
                          endAngle={-270}
                        >
                          {detectionData.map((entry) => (
                            <Cell key={entry.name} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={TOOLTIP_STYLE} />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="donut-center">
                      <span className="donut-center-value">{alertList.length}</span>
                      <span className="donut-center-label">Alerts</span>
                    </div>
                  </div>
                  <div className="donut-legend">
                    {detectionData.map((entry) => (
                      <div className="donut-legend-row" key={entry.name}>
                        <span className="donut-legend-dot" style={{ background: entry.color }} />
                        <span className="donut-legend-name">{entry.name}</span>
                        <span className="donut-legend-count">{entry.value}</span>
                      </div>
                    ))}
                    <p className="donut-legend-note">
                      Detection source per alert: rule engine vs. Isolation Forest anomaly model.
                    </p>
                  </div>
                </div>
              ) : (
                <EmptyState title="No detections yet" />
              )}
            </section>

            <section className="panel" data-testid="analytics-risk-distribution">
              <div className="panel-head">
                <h2 className="panel-title">Risk Distribution</h2>
                <span className="panel-tag">{incidentList.length} incidents by risk level</span>
              </div>
              {incidentList.length > 0 ? (
                <div className="attack-type-list">
                  {riskData.map((row) => (
                    <div className="attack-type-row" key={row.name}>
                      <div className="attack-type-head">
                        <span className="attack-type-name">{row.name}</span>
                        <span className="attack-type-stats">
                          <b>{row.value}</b> incident{row.value === 1 ? '' : 's'}
                        </span>
                      </div>
                      <div className="attack-bar">
                        <div
                          className="attack-bar-fill"
                          style={{
                            width: `${
                              (row.value / Math.max(...riskData.map((r) => r.value), 1)) * 100
                            }%`,
                            background: RISK_COLORS[row.name],
                          }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState title="No incidents yet" />
              )}
            </section>
          </div>

          <div className="grid analytics-grid">
            <section className="panel" data-testid="analytics-attack-stages">
              <div className="panel-head">
                <h2 className="panel-title">Attack Stages</h2>
                <span className="panel-tag">Observed across incidents</span>
              </div>
              {attackStages.length > 0 ? (
                <div className="attack-type-list">
                  {attackStages.map((row) => (
                    <div className="attack-type-row" key={row.name}>
                      <div className="attack-type-head">
                        <span className="attack-type-name">{row.name}</span>
                        <span className="attack-type-stats">
                          <b>{row.count}</b> incident{row.count === 1 ? '' : 's'}
                        </span>
                      </div>
                      <div className="attack-bar">
                        <div className="attack-bar-fill" style={{ width: `${row.width}%` }} />
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No attack stages observed"
                  hint="Correlated incidents carry potential attack stages."
                />
              )}
            </section>

            <section className="panel" data-testid="analytics-attack-types">
              <div className="panel-head">
                <h2 className="panel-title">Top Attack Types</h2>
                <span className="panel-tag">{eventList.length} events by type</span>
              </div>
              {attackTypes.length > 0 ? (
                <div className="attack-type-list">
                  {attackTypes.map((row) => (
                    <div className="attack-type-row" key={row.name}>
                      <div className="attack-type-head">
                        <span className="attack-type-name mono">{row.name}</span>
                        <span className="attack-type-stats">
                          <b>{row.count}</b> · {row.share}%
                        </span>
                      </div>
                      <div className="attack-bar">
                        <div className="attack-bar-fill" style={{ width: `${row.width}%` }} />
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState title="No events yet" hint="Ingest events to see attack types." />
              )}
            </section>
          </div>

          <section className="panel" data-testid="analytics-ml">
            <div className="panel-head">
              <h2 className="panel-title">ML Anomalies</h2>
              <span className="panel-tag">
                {mlStatus.data?.model_loaded ? mlStatus.data.detection_method.replace(/_/g, ' ') : 'model standby'}
              </span>
            </div>
            <div className="info-grid">
              <div className="info-row">
                <span className="info-label">ML anomaly alerts</span>
                <span className="info-value mono">{mlAlerts.length}</span>
              </div>
              <div className="info-row">
                <span className="info-label">Share of all alerts</span>
                <span className="info-value mono">
                  {alertList.length > 0
                    ? `${Math.round((mlAlerts.length / alertList.length) * 100)}%`
                    : '—'}
                </span>
              </div>
              <div className="info-row">
                <span className="info-label">Model loaded</span>
                <span className="info-value mono">
                  {mlStatus.data?.model_loaded ? 'YES' : 'NO'}
                </span>
              </div>
              <div className="info-row">
                <span className="info-label">Training samples</span>
                <span className="info-value mono">{mlStatus.data?.training_samples ?? '—'}</span>
              </div>
              <div className="info-row">
                <span className="info-label">Threshold</span>
                <span className="info-value mono">{mlStatus.data?.threshold ?? '—'}</span>
              </div>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
