import { NavLink, Route, Routes } from 'react-router-dom';
import { useApi } from '@/hooks/useApi';
import { api } from '@/api/nexus';
import DashboardPage from '@/pages/DashboardPage';
import IncidentsPage from '@/pages/IncidentsPage';
import IncidentDetailPage from '@/pages/IncidentDetailPage';
import AlertsPage from '@/pages/AlertsPage';
import ThreatIntelPage from '@/pages/ThreatIntelPage';
import AiInvestigatorPage from '@/pages/AiInvestigatorPage';
import ReportsPage from '@/pages/ReportsPage';
import AssetsPage from '@/pages/AssetsPage';
import AnalyticsPage from '@/pages/AnalyticsPage';
import SettingsPage from '@/pages/SettingsPage';
import SystemStatus from '@/components/SystemStatus';
import {
  IconAlerts,
  IconAnalytics,
  IconAssets,
  IconBell,
  IconCpu,
  IconDashboard,
  IconIncidents,
  IconInvestigator,
  IconReports,
  IconSearch,
  IconSettings,
  IconShield,
  IconThreatIntel,
} from '@/components/icons';

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: IconDashboard, end: true },
  { to: '/incidents', label: 'Incidents', icon: IconIncidents },
  { to: '/alerts', label: 'Alerts', icon: IconAlerts },
  { to: '/threat-intelligence', label: 'Threat Intelligence', icon: IconThreatIntel },
  { to: '/ai-investigator', label: 'AI Investigator', icon: IconInvestigator },
  { to: '/reports', label: 'Reports', icon: IconReports },
  { to: '/assets', label: 'Assets', icon: IconAssets },
  { to: '/analytics', label: 'Analytics', icon: IconAnalytics },
  { to: '/settings', label: 'Settings', icon: IconSettings },
];

export default function App() {
  const health = useApi(() => api.health(), [], { pollMs: 30_000 });
  const ml = useApi(() => api.mlStatus(), [], { pollMs: 60_000 });
  const newAlerts = useApi(() => api.listAlerts({ status: 'new', limit: 500 }), [], {
    pollMs: 30_000,
  });

  const ok = health.data?.status === 'healthy';
  const untriaged = (newAlerts.data ?? []).length;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="brand-mark" aria-hidden="true">
            <IconShield size={17} />
          </span>
          <div className="brand-text">
            <span className="brand-name">
              NEXUS <em>ONE</em>
            </span>
            <span className="brand-sub">AI-Powered SOC</span>
          </div>
        </div>

        <div className="sidebar-section">Operations Console</div>
        <nav className="sidebar-nav" aria-label="Primary">
          {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
            >
              <span className="nav-icon">
                <Icon size={17} />
              </span>
              <span>{label}</span>
              {to === '/incidents' && untriaged > 0 ? (
                <span className="nav-count">{untriaged}</span>
              ) : null}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-status">
          <div className="sidebar-status-head">
            <span>System Status</span>
            <span className="status-badge">
              <span className="status-dot" aria-hidden="true" />
              {ok ? 'SECURE' : 'ALERT'}
            </span>
          </div>
          <div className="sidebar-status-rows">
            <span>
              ENGINE <b>{ok ? 'ONLINE' : 'OFFLINE'}</b>
            </span>
            <span>
              DATABASE <b>{health.data ? health.data.database.toUpperCase() : '—'}</b>
            </span>
            <span>
              ML MODEL <b>{ml.data?.model_loaded ? 'LOADED' : 'STANDBY'}</b>
            </span>
          </div>
        </div>
      </aside>

      <header className="topnav">
        <div className="global-search">
          <IconSearch size={15} />
          <input
            type="search"
            placeholder="Search incidents, alerts, IPs, users..."
            aria-label="Search incidents, alerts, IPs, users"
          />
          <kbd>⌘K</kbd>
        </div>
        <div className="topnav-actions">
          <button type="button" className="icon-btn" aria-label={`Notifications: ${untriaged} untriaged alerts`}>
            <IconBell size={16} />
            {untriaged > 0 ? <span className="notif-count">{untriaged > 99 ? '99+' : untriaged}</span> : null}
          </button>
          <SystemStatus health={health.data} />
          <div className="analyst-chip">
            <span className="analyst-avatar" aria-hidden="true">
              N1
            </span>
            <div className="analyst-meta">
              <span className="analyst-name">SOC Analyst</span>
              <span className="analyst-role">Tier 2 · Response</span>
            </div>
          </div>
        </div>
      </header>

      <main className="app-main">
        <div className="content-wide">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/incidents" element={<IncidentsPage />} />
            <Route path="/incidents/:incidentId" element={<IncidentDetailPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/threat-intelligence" element={<ThreatIntelPage />} />
            <Route path="/ai-investigator" element={<AiInvestigatorPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<div className="empty-state">Page not found.</div>} />
          </Routes>
        </div>
      </main>

      <footer className="activity-bar">
        <span className="activity-item">
          <span className={`activity-dot ${ok ? 'ok' : 'down'}`} aria-hidden="true" />
          <b>NEXUS ONE ENGINE</b> {ok ? 'ONLINE' : 'OFFLINE'}
        </span>
        <span className="activity-item">
          <IconCpu size={12} />
          <b>ML</b> {ml.data?.model_loaded ? `LOADED · ${ml.data.detection_method}` : 'STANDBY'}
        </span>
        <span className="activity-item">
          <b>DB</b> {health.data ? health.data.database.toUpperCase() : '—'}
        </span>
        <span className="activity-item">
          <b>ENV</b> {health.data ? health.data.environment.toUpperCase() : '—'}
        </span>
        <span className="activity-spacer" />
        <span className="activity-updated">
          {health.lastUpdated ? `SYNCED ${health.lastUpdated.toLocaleTimeString()}` : 'AWAITING SYNC'}
        </span>
      </footer>
    </div>
  );
}
