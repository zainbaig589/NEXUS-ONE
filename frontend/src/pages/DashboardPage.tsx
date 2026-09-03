/**
 * OPERATIONS DASHBOARD — SOC command center.
 *
 * Three visual tiers: KPI row (real backend counts + real time-bucketed
 * sparklines) → Security Operations Flow hero (telemetry tunnel) with the
 * Live Threat Feed beside it → lower analytics (Incidents Over Time, Risk
 * Distribution, Top Attack Types, Detection Methods) and the Recent
 * Incidents table linking to the detail pages.
 * Every number comes from the API; nothing is fabricated.
 */

import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { api, ApiError } from '@/api/nexus';
import { useApi } from '@/hooks/useApi';
import KpiCard from '@/components/KpiCard';
import SecurityOperationsFlow from '@/components/SecurityOperationsFlow';
import SeverityBadge from '@/components/SeverityBadge';
import DemoPipeline from '@/components/DemoPipeline';
import { EmptyState, ErrorBanner, Loading } from '@/components/States';
import {
  formatDateTime,
  formatTime,
  normalizeSeverity,
  riskLevelColor,
  SEVERITY_ORDER,
  shortId,
} from '@/utils/format';
import {
  IconActivity,
  IconAlerts,
  IconCpu,
  IconIncidents,
  IconShield,
  IconZap,
} from '@/components/icons';
import type { DemoAttackScenarioResponse, Incident } from '@/types';

const SEVERITY_CHART_COLORS: Record<string, string> = {
  critical: '#f43f5e',
  high: '#f97316',
  medium: '#eab308',
  low: '#38bdf8',
  info: '#64748b',
};

const TOOLTIP_STYLE = {
  backgroundColor: '#0b1220',
  border: '1px solid rgba(34, 211, 238, 0.25)',
  borderRadius: 6,
  fontSize: 12,
  color: '#e2e8f0',
  boxShadow: '0 6px 24px rgba(2, 6, 14, 0.6)',
};

/** Buckets real timestamps into 12 equal slices; null when there is no trend yet. */
function sparkFrom(dates: (string | null | undefined)[]): number[] | null {
  const times = dates
    .filter((d): d is string => Boolean(d))
    .map((d) => new Date(d).getTime())
    .filter((t) => !Number.isNaN(t));
  if (times.length < 2) return null;
  const min = Math.min(...times);
  const span = Math.max(...times) - min || 1;
  const buckets = new Array<number>(12).fill(0);
  for (const t of times) {
    buckets[Math.min(11, Math.floor(((t - min) / span) * 12))] += 1;
  }
  return buckets;
}

export default function DashboardPage() {
  const incidents = useApi(() => api.listIncidents({ limit: 200 }), [], { pollMs: 30_000 });
  const alerts = useApi(() => api.listAlerts({ limit: 500 }), [], { pollMs: 30_000 });
  const events = useApi(() => api.listEvents({ limit: 500 }), [], { pollMs: 30_000 });
  const mlStatus = useApi(() => api.mlStatus(), [], { pollMs: 60_000 });

  const navigate = useNavigate();
  const [scenarioRunning, setScenarioRunning] = useState(false);
  const [scenarioResult, setScenarioResult] = useState<DemoAttackScenarioResponse | null>(null);
  const [scenarioError, setScenarioError] = useState<string | null>(null);

  const incidentList: Incident[] = incidents.data ?? [];
  const alertList = alerts.data ?? [];
  const eventList = events.data ?? [];

  const mlHint = useMemo(() => {
    const method = mlStatus.data?.model_loaded ? mlStatus.data.detection_method : null;
    return method ? `Detected by ${method.replace(/_/g, ' ')}` : 'ML anomaly detection';
  }, [mlStatus.data]);

  const metrics = useMemo(() => {
    const critical = incidentList.filter((i) => normalizeSeverity(i.severity) === 'critical');
    const highRisk = incidentList.filter(
      (i) => i.risk_level === 'HIGH' || i.risk_level === 'CRITICAL',
    );
    const newAlerts = alertList.filter((a) => a.status === 'new');
    const mlAlerts = alertList.filter((a) => a.detection_source === 'ml');
    return {
      total: incidentList.length,
      critical: critical.length,
      highRisk: highRisk.length,
      activeAlerts: newAlerts.length,
      mlAnomalies: mlAlerts.length,
      criticalSpark: sparkFrom(critical.map((i) => i.created_at)),
      highRiskSpark: sparkFrom(highRisk.map((i) => i.created_at)),
      activeAlertsSpark: sparkFrom(newAlerts.map((a) => a.created_at)),
      mlSpark: sparkFrom(mlAlerts.map((a) => a.created_at)),
      totalSpark: sparkFrom(incidentList.map((i) => i.created_at)),
    };
  }, [incidentList, alertList]);

  const severityData = useMemo(
    () =>
      SEVERITY_ORDER.map((severity) => ({
        name: severity,
        value: incidentList.filter((i) => normalizeSeverity(i.severity) === severity).length,
      })),
    [incidentList],
  );

  /**
   * Detection methods over real API objects: alerts by their detection_source
   * (RULE / ML / OTHER) plus CORRELATION — the incidents the correlation
   * engine built from correlated alerts. Units are labeled in the legend.
   */
  const detectionData = useMemo(() => {
    const rule = alertList.filter((a) => a.detection_source === 'rule').length;
    const ml = alertList.filter((a) => a.detection_source === 'ml').length;
    const other = alertList.length - rule - ml;
    return [
      { name: 'RULE', value: rule, color: '#38bdf8', unit: 'alerts' },
      { name: 'ML', value: ml, color: '#a78bfa', unit: 'alerts' },
      { name: 'CORRELATION', value: incidentList.length, color: '#22d3ee', unit: 'incidents' },
      { name: 'OTHER', value: other, color: '#64748b', unit: 'alerts' },
    ];
  }, [alertList, incidentList]);

  const detectionTotal = useMemo(
    () => detectionData.reduce((sum, entry) => sum + entry.value, 0),
    [detectionData],
  );

  const recentIncidents = useMemo(
    () =>
      [...incidentList]
        .sort(
          (a, b) =>
            new Date(b.last_seen ?? b.created_at).getTime() -
            new Date(a.last_seen ?? a.created_at).getTime(),
        )
        .slice(0, 8),
    [incidentList],
  );

  const liveAlerts = useMemo(
    () =>
      [...alertList]
        .sort(
          (a, b) =>
            new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
        )
        .slice(0, 14),
    [alertList],
  );

  const attackTypes = useMemo(() => {
    const counts = new Map<string, number>();
    for (const alert of alertList) {
      const name = alert.rule_name || 'Unknown rule';
      counts.set(name, (counts.get(name) ?? 0) + 1);
    }
    const max = Math.max(...counts.values(), 1);
    return [...counts.entries()]
      .map(([name, count]) => ({ name, count, share: Math.round((count / alertList.length) * 100) }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6)
      .map((row) => ({ ...row, width: Math.round((row.count / max) * 100) }));
  }, [alertList]);

  const timelineData = useMemo(() => {
    const times = incidentList
      .map((i) => new Date(i.created_at ?? i.first_seen ?? '').getTime())
      .filter((t) => !Number.isNaN(t));
    if (times.length < 2) return null;
    const min = Math.min(...times);
    const max = Math.max(...times);
    const span = max - min || 1;
    const useDays = span > 24 * 3600_000;
    const buckets = new Array<number>(12).fill(0);
    for (const t of times) {
      buckets[Math.min(11, Math.floor(((t - min) / span) * 12))] += 1;
    }
    return buckets.map((count, i) => {
      const start = new Date(min + (span / 12) * i);
      return {
        label: useDays
          ? start.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
          : start.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false }),
        count,
      };
    });
  }, [incidentList]);

  async function runScenario() {
    setScenarioRunning(true);
    setScenarioError(null);
    setScenarioResult(null);
    try {
      const result = await api.runDemoScenario();
      setScenarioResult(result);
      await Promise.all([
        incidents.refresh(),
        alerts.refresh(),
        events.refresh(),
        mlStatus.refresh(),
      ]);
    } catch (err) {
      setScenarioError(err instanceof ApiError ? err.message : 'Failed to run attack scenario.');
    } finally {
      setScenarioRunning(false);
    }
  }

  function refreshAll() {
    void incidents.refresh();
    void alerts.refresh();
    void events.refresh();
    void mlStatus.refresh();
  }

  const loading = incidents.loading && alerts.loading;
  const hasSeverityData = severityData.some((d) => d.value > 0);

  return (
    <div className="page-dashboard">
      <div className="page-header">
        <div>
          <h1 className="page-title">
            Operations Dashboard
            <span className="page-title-accent">//</span> Nexus One
          </h1>
          <p className="page-subtitle">
            Security operations command center
            {incidents.lastUpdated ? ` — updated ${formatDateTime(incidents.lastUpdated)}` : ''}
          </p>
        </div>
        <div className="page-actions">
          <button
            type="button"
            className="btn"
            onClick={refreshAll}
            disabled={incidents.refreshing || alerts.refreshing}
          >
            Refresh
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => void runScenario()}
            disabled={scenarioRunning}
            data-testid="run-scenario"
          >
            {scenarioRunning ? 'Running scenario…' : 'Run Attack Scenario'}
          </button>
        </div>
      </div>

      {incidents.error ? (
        <ErrorBanner message={incidents.error} onRetry={incidents.refresh} />
      ) : null}
      {alerts.error ? <ErrorBanner message={alerts.error} onRetry={alerts.refresh} /> : null}
      {scenarioError ? <ErrorBanner message={scenarioError} /> : null}

      {(scenarioRunning || scenarioResult) && (
        <DemoPipeline
          running={scenarioRunning}
          result={scenarioResult}
          onViewIncident={(id) => navigate(`/incidents/${id}`)}
        />
      )}

      {loading ? (
        <Loading label="Loading dashboard…" />
      ) : (
        <>
          <div className="grid kpi-grid">
            <KpiCard
              label="Total Incidents"
              value={metrics.total}
              hint="All correlated incidents"
              icon={<IconIncidents size={16} />}
              color="var(--accent)"
              testId="metric-total-incidents"
              spark={metrics.totalSpark}
            />
            <KpiCard
              label="Critical Incidents"
              value={metrics.critical}
              hint="Severity: critical"
              icon={<IconZap size={16} />}
              color="var(--critical)"
              testId="metric-critical-incidents"
              spark={metrics.criticalSpark}
            />
            <KpiCard
              label="High-Risk Incidents"
              value={metrics.highRisk}
              hint="Risk level HIGH or CRITICAL"
              icon={<IconShield size={16} />}
              color="var(--high)"
              testId="metric-high-risk"
              spark={metrics.highRiskSpark}
            />
            <KpiCard
              label="Active Alerts"
              value={metrics.activeAlerts}
              hint="Alerts awaiting triage"
              icon={<IconAlerts size={16} />}
              color="var(--medium)"
              testId="metric-active-alerts"
              spark={metrics.activeAlertsSpark}
            />
            <KpiCard
              label="ML Anomalies"
              value={metrics.mlAnomalies}
              hint={mlHint}
              icon={<IconCpu size={16} />}
              color="var(--violet)"
              testId="metric-ml-anomalies"
              spark={metrics.mlSpark}
            />
          </div>

          <div className="grid grid-dashboard">
            <SecurityOperationsFlow events={eventList} incidents={incidentList} alerts={alertList} />

            <section className="panel feed-panel" data-testid="threat-feed">
              <div className="panel-head">
                <h2 className="panel-title">
                  <span className="feed-live-dot" aria-hidden="true" />
                  <IconActivity size={13} className="panel-title-accent" />
                  Live Threat Feed
                </h2>
                <span className="panel-tag">{metrics.activeAlerts} active</span>
              </div>
              {liveAlerts.length > 0 ? (
                <div className="feed-list">
                  {liveAlerts.map((alert) => {
                    const level = normalizeSeverity(alert.severity);
                    return (
                      <div key={alert.id} className={`feed-item ${level}`}>
                        <span
                          className="feed-sev-dot"
                          style={{ background: SEVERITY_CHART_COLORS[level] }}
                          aria-hidden="true"
                        />
                        <div className="feed-body">
                          <div className="feed-title-row">
                            <span className="feed-rule">{alert.rule_name}</span>
                            <SeverityBadge severity={alert.severity} />
                          </div>
                          <div className="feed-desc">{alert.description}</div>
                          <div className="feed-meta">
                            <span className="feed-time">{formatTime(alert.created_at)}</span>
                            <span
                              className={`feed-src ${alert.detection_source === 'ml' ? 'ml' : 'rule'}`}
                            >
                              {alert.detection_source === 'ml' ? 'ML' : 'RULE'}
                            </span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <EmptyState
                  title="Feed is quiet"
                  hint="New detections stream in here in real time."
                />
              )}
            </section>
          </div>

          <div className="grid grid-lower-a">
            <section className="panel panel-timeline" data-testid="timeline-chart">
              <div className="panel-head">
                <h2 className="panel-title">Incidents Over Time</h2>
                <span className="panel-tag">{metrics.total} incidents</span>
              </div>
              {timelineData ? (
                <ResponsiveContainer width="100%" height={210}>
                  <AreaChart data={timelineData} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                    <defs>
                      <linearGradient id="incidents-area" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.32} />
                        <stop offset="100%" stopColor="#22d3ee" stopOpacity={0.02} />
                      </linearGradient>
                      <linearGradient id="incidents-line" x1="0" y1="0" x2="1" y2="0">
                        <stop offset="0%" stopColor="#38bdf8" />
                        <stop offset="100%" stopColor="#22d3ee" />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="rgba(34, 211, 238, 0.08)" vertical={false} />
                    <XAxis
                      dataKey="label"
                      stroke="#64748b"
                      fontSize={10}
                      tickLine={false}
                      axisLine={{ stroke: '#22304d' }}
                      minTickGap={26}
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
                    <Area
                      type="monotone"
                      dataKey="count"
                      name="Incidents"
                      stroke="url(#incidents-line)"
                      strokeWidth={2}
                      fill="url(#incidents-area)"
                      dot={false}
                      activeDot={{ r: 4, fill: '#22d3ee', stroke: '#0b1220' }}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState
                  title="Not enough history yet"
                  hint="Incident timestamps will draw the trend line as data accumulates."
                />
              )}
            </section>

            <section className="panel" data-testid="severity-chart">
              <div className="panel-head">
                <h2 className="panel-title">Risk Distribution</h2>
                <span className="panel-tag">By incident severity</span>
              </div>
              {hasSeverityData ? (
                <div className="risk-compact">
                  <div className="donut-wrap donut-fixed donut-sm">
                    <ResponsiveContainer width={170} height={170}>
                      <PieChart>
                        <Pie
                          data={severityData.filter((d) => d.value > 0)}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          innerRadius={56}
                          outerRadius={78}
                          paddingAngle={3}
                          cornerRadius={4}
                          stroke="none"
                          startAngle={90}
                          endAngle={-270}
                        >
                          {severityData
                            .filter((d) => d.value > 0)
                            .map((entry) => (
                              <Cell key={entry.name} fill={SEVERITY_CHART_COLORS[entry.name]} />
                            ))}
                        </Pie>
                        <Tooltip contentStyle={TOOLTIP_STYLE} />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="donut-center">
                      <span className="donut-center-value">{metrics.total}</span>
                      <span className="donut-center-label">Incidents</span>
                    </div>
                  </div>
                  <div className="risk-legend risk-legend-grid">
                    {severityData.map((entry) => (
                      <div className="risk-legend-row" key={entry.name}>
                        <span
                          className="risk-legend-dot"
                          style={{ background: SEVERITY_CHART_COLORS[entry.name] }}
                        />
                        <span className="risk-legend-name">{entry.name.toUpperCase()}</span>
                        <span className="risk-legend-count">{entry.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <EmptyState
                  title="No incidents yet"
                  hint="Run the attack scenario to generate data."
                />
              )}
            </section>

            <section className="panel" data-testid="attack-types">
              <div className="panel-head">
                <h2 className="panel-title">Top Attack Types</h2>
                <span className="panel-tag">{alertList.length} alerts</span>
              </div>
              {attackTypes.length > 0 ? (
                <div className="attack-type-list">
                  {attackTypes.map((row) => (
                    <div className="attack-type-row" key={row.name}>
                      <div className="attack-type-head">
                        <span className="attack-type-name">{row.name}</span>
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
                <EmptyState
                  title="No alerts yet"
                  hint="Run the attack scenario to generate detections."
                />
              )}
            </section>
          </div>

          <div className="grid grid-lower-b">
            <section className="panel" data-testid="detection-chart">
              <div className="panel-head">
                <h2 className="panel-title">Detection Methods</h2>
                <span className="panel-tag">
                  {alertList.length} alerts · {incidentList.length} incidents
                </span>
              </div>
              {detectionTotal > 0 ? (
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
                      <span className="donut-center-value">{detectionTotal}</span>
                      <span className="donut-center-label">Detections</span>
                    </div>
                  </div>
                  <div className="donut-legend">
                    {detectionData.map((entry) => (
                      <div className="donut-legend-row" key={entry.name}>
                        <span className="donut-legend-dot" style={{ background: entry.color }} />
                        <span className="donut-legend-name">
                          {entry.name}
                          <i>{entry.unit}</i>
                        </span>
                        <span className="donut-legend-count">{entry.value}</span>
                      </div>
                    ))}
                    <p className="donut-legend-note">
                      Correlation counts incidents the engine built from correlated alerts.
                    </p>
                  </div>
                </div>
              ) : (
                <EmptyState
                  title="No detections yet"
                  hint="Run the attack scenario to generate data."
                />
              )}
            </section>

            <section className="panel" data-testid="recent-incidents">
              <div className="panel-head">
                <h2 className="panel-title">Recent Incidents</h2>
                <Link to="/incidents" className="panel-link">
                  View all
                </Link>
              </div>
              {recentIncidents.length > 0 ? (
                <div className="incident-table-wrap">
                  <table className="incident-table">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Incident</th>
                        <th>Severity</th>
                        <th>Risk</th>
                        <th>Alerts</th>
                        <th>Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recentIncidents.map((incident) => (
                        <tr
                          key={incident.id}
                          onClick={() => navigate(`/incidents/${incident.id}`)}
                        >
                          <td className="incident-table-id mono">{shortId(incident.id)}</td>
                          <td className="incident-table-title">{incident.title}</td>
                          <td>
                            <SeverityBadge severity={incident.severity} />
                          </td>
                          <td
                            className="incident-table-risk mono"
                            style={{ color: riskLevelColor(incident.risk_level) }}
                          >
                            {incident.risk_score != null ? incident.risk_score.toFixed(0) : '—'}
                            <i>{incident.risk_level || '—'}</i>
                          </td>
                          <td className="incident-table-count mono">{incident.alert_count}</td>
                          <td className="incident-table-time">
                            {formatDateTime(incident.last_seen ?? incident.created_at)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <EmptyState
                  title="No incidents recorded"
                  hint="Ingest events via the API or run the attack scenario above."
                />
              )}
            </section>
          </div>
        </>
      )}
    </div>
  );
}
