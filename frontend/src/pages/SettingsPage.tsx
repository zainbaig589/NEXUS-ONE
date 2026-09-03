/**
 * SYSTEM STATUS & CONFIGURATION — surfaces runtime status from /health and
 * /api/v1/ml/status plus the AI provider actually used by the most recent
 * investigation. The backend never returns secret values, and none are shown.
 */
import { useEffect, useState } from 'react';
import { api } from '@/api/nexus';
import { useApi } from '@/hooks/useApi';
import { EmptyState, ErrorBanner } from '@/components/States';
import { formatDateTime } from '@/utils/format';
import type { InvestigationResponse } from '@/types';

const PROVIDER_LABELS: Record<string, string> = {
  demo: 'Deterministic demo provider (no live LLM)',
  openai: 'OpenAI-compatible endpoint',
};

export default function SettingsPage() {
  const health = useApi(() => api.health(), [], { pollMs: 30_000 });
  const mlStatus = useApi(() => api.mlStatus(), [], { pollMs: 30_000 });
  const incidents = useApi(() => api.listIncidents({ limit: 20 }), [], { pollMs: 60_000 });

  const [provider, setProvider] = useState<InvestigationResponse | null>(null);
  const [providerChecked, setProviderChecked] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const incidentIds = (incidents.data ?? []).slice(0, 5).map((i) => i.id);
    if (incidentIds.length === 0) {
      setProvider(null);
      setProviderChecked(true);
      return () => {
        cancelled = true;
      };
    }
    setProviderChecked(false);
    void (async () => {
      let found: InvestigationResponse | null = null;
      for (const id of incidentIds) {
        try {
          const investigation = await api.getInvestigation(id);
          if (investigation) {
            found = investigation;
            break;
          }
        } catch {
          // provider lookup is best-effort; keep scanning
        }
      }
      if (!cancelled) {
        setProvider(found);
        setProviderChecked(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [incidents.data]);

  const isDemo = provider?.analysis_mode?.toUpperCase().includes('DEMO') ?? false;
  const ok = health.data?.status === 'healthy';

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">System Status & Configuration</h1>
          <p className="page-subtitle">
            Runtime status of the Nexus One engine, database, ML model, and AI provider.
          </p>
        </div>
        <div className="page-actions">
          <button
            type="button"
            className="btn"
            onClick={() => {
              void health.refresh();
              void mlStatus.refresh();
              void incidents.refresh();
            }}
            disabled={health.refreshing || mlStatus.refreshing}
          >
            {health.refreshing || mlStatus.refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      {health.error ? <ErrorBanner message={health.error} onRetry={health.refresh} /> : null}
      {mlStatus.error ? <ErrorBanner message={mlStatus.error} onRetry={mlStatus.refresh} /> : null}

      <div className="grid settings-grid">
        <section className="panel" data-testid="settings-api">
          <div className="panel-head">
            <h2 className="panel-title">API Status</h2>
            <span
              className={`badge ${ok ? 'badge-open' : 'badge-closed'}`}
              style={{ textTransform: 'none' }}
            >
              {ok ? 'Healthy' : health.data ? health.data.status : 'Unknown'}
            </span>
          </div>
          <div className="info-grid">
            <div className="info-row">
              <span className="info-label">Service</span>
              <span className="info-value">{health.data?.app_name ?? '—'}</span>
            </div>
            <div className="info-row">
              <span className="info-label">Version</span>
              <span className="info-value mono">{health.data?.version ?? '—'}</span>
            </div>
            <div className="info-row">
              <span className="info-label">Last check</span>
              <span className="info-value">
                {health.lastUpdated ? formatDateTime(health.lastUpdated) : '—'}
              </span>
            </div>
          </div>
        </section>

        <section className="panel" data-testid="settings-database">
          <div className="panel-head">
            <h2 className="panel-title">Database Status</h2>
            <span
              className={`badge ${health.data?.database === 'connected' ? 'badge-open' : 'badge-closed'}`}
              style={{ textTransform: 'none' }}
            >
              {health.data ? health.data.database : '—'}
            </span>
          </div>
          <div className="info-grid">
            <div className="info-row">
              <span className="info-label">Connection</span>
              <span className="info-value">
                {health.data?.database === 'connected'
                  ? 'SQLite — reachable'
                  : health.data
                    ? 'Check backend logs'
                    : '—'}
              </span>
            </div>
            <div className="info-row">
              <span className="info-label">API key / credentials</span>
              <span className="info-value" style={{ color: 'var(--text-dim)' }}>
                Never returned by the API
              </span>
            </div>
          </div>
        </section>

        <section className="panel" data-testid="settings-ml">
          <div className="panel-head">
            <h2 className="panel-title">ML Model Status</h2>
            <span
              className={`badge ${mlStatus.data?.model_loaded ? 'badge-open' : 'badge-neutral'}`}
              style={{ textTransform: 'none' }}
            >
              {mlStatus.data?.model_loaded ? 'Loaded' : 'Standby'}
            </span>
          </div>
          <div className="info-grid">
            <div className="info-row">
              <span className="info-label">Detection method</span>
              <span className="info-value">
                {mlStatus.data?.detection_method
                  ? mlStatus.data.detection_method.replace(/_/g, ' ')
                  : '—'}
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
            <div className="info-row">
              <span className="info-label">Model path</span>
              <span className="info-value mono" style={{ fontSize: 11 }}>
                {mlStatus.data?.model_path ?? '—'}
              </span>
            </div>
            <div className="info-row">
              <span className="info-label">Features</span>
              <span className="info-value mono" style={{ fontSize: 11 }}>
                {mlStatus.data?.features?.length ? mlStatus.data.features.join(', ') : '—'}
              </span>
            </div>
          </div>
        </section>

        <section className="panel" data-testid="settings-provider">
          <div className="panel-head">
            <h2 className="panel-title">AI Provider</h2>
            {provider ? (
              <span className={`badge ${isDemo ? 'badge-demo' : 'badge-live'}`}>
                {isDemo ? 'DEMO MODE' : 'LIVE LLM'}
              </span>
            ) : null}
          </div>
          {provider ? (
            <div className="info-grid">
              <div className="info-row">
                <span className="info-label">Provider</span>
                <span className="info-value">
                  {provider.provider}
                  {PROVIDER_LABELS[provider.provider] ? (
                    <span style={{ color: 'var(--text-muted)' }}>
                      {' '}
                      — {PROVIDER_LABELS[provider.provider]}
                    </span>
                  ) : null}
                </span>
              </div>
              <div className="info-row">
                <span className="info-label">Analysis mode</span>
                <span className="info-value">{provider.analysis_mode}</span>
              </div>
              <div className="info-row">
                <span className="info-label">Last investigation</span>
                <span className="info-value">{formatDateTime(provider.generated_at)}</span>
              </div>
              <div className="info-row">
                <span className="info-label">API key</span>
                <span className="info-value" style={{ color: 'var(--text-dim)' }}>
                  Never returned by the API
                </span>
              </div>
            </div>
          ) : providerChecked ? (
            <EmptyState
              title="No investigation has been run yet"
              hint="Run an investigation from an incident (or the AI Investigator page) to identify the active provider."
            />
          ) : (
            <EmptyState title="Checking provider…" />
          )}
        </section>

        <section className="panel" data-testid="settings-environment">
          <div className="panel-head">
            <h2 className="panel-title">Environment</h2>
            <span className="badge badge-neutral" style={{ textTransform: 'none' }}>
              {health.data?.environment ?? '—'}
            </span>
          </div>
          <div className="info-grid">
            <div className="info-row">
              <span className="info-label">APP_ENV</span>
              <span className="info-value mono">{health.data?.environment ?? '—'}</span>
            </div>
            <div className="info-row">
              <span className="info-label">Configuration</span>
              <span className="info-value" style={{ color: 'var(--text-dim)' }}>
                Provider keys and secrets are never exposed
              </span>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
