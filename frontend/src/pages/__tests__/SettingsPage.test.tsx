import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import SettingsPage from '@/pages/SettingsPage';
import { installFetchMock, failFetch, type RouteTable } from '@/test/apiMock';
import { INCIDENT_ID, health, incident, investigation, mlStatus } from '@/test/fixtures';

function installRoutes(overrides: RouteTable = {}): ReturnType<typeof installFetchMock> {
  return installFetchMock({
    '/health': { body: health },
    '/api/v1/ml/status': { body: mlStatus },
    '/api/v1/incidents/': { body: [incident] },
    [`/api/v1/incidents/${INCIDENT_ID}/investigation`]: { body: investigation },
    ...overrides,
  });
}

describe('SettingsPage', () => {
  it('surfaces API, database, ML, and environment status without secrets', async () => {
    installRoutes();

    render(<SettingsPage />);

    const apiPanel = await screen.findByTestId('settings-api');
    expect(apiPanel).toHaveTextContent('Healthy');
    expect(apiPanel).toHaveTextContent('Nexus One');
    expect(apiPanel).toHaveTextContent('1.0.0');

    const db = screen.getByTestId('settings-database');
    expect(db).toHaveTextContent('connected');
    expect(db).toHaveTextContent('SQLite — reachable');

    const ml = screen.getByTestId('settings-ml');
    expect(ml).toHaveTextContent('Loaded');
    expect(ml).toHaveTextContent('isolation forest');
    expect(ml).toHaveTextContent('1200');
    expect(ml).toHaveTextContent('0.62');
    expect(ml).toHaveTextContent('failed_attempts, bytes_transferred, privilege_flag');

    const env = screen.getByTestId('settings-environment');
    expect(env).toHaveTextContent('development');

    // Secrets are never displayed — only the explicit policy note.
    expect(screen.getAllByText('Never returned by the API').length).toBeGreaterThan(0);
  });

  it('identifies the AI provider from the latest investigation', async () => {
    installRoutes();

    render(<SettingsPage />);

    const provider = await screen.findByTestId('settings-provider');
    await waitFor(() => {
      expect(provider).toHaveTextContent('DEMO MODE');
    });
    expect(provider).toHaveTextContent('demo');
    expect(provider).toHaveTextContent('Deterministic demo provider (no live LLM)');
    expect(provider).toHaveTextContent('DEMO (deterministic mock provider - not a live LLM)');
  });

  it('reports when no investigation has been run yet', async () => {
    installRoutes({
      [`/api/v1/incidents/${INCIDENT_ID}/investigation`]: {
        status: 404,
        body: { detail: 'No investigation has been run' },
      },
    });

    render(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getByText('No investigation has been run yet')).toBeInTheDocument();
    });
  });

  it('shows a graceful error when the API is unreachable', async () => {
    failFetch();

    render(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getAllByText(/Cannot reach the Nexus One API/i).length).toBeGreaterThan(0);
    });
  });
});
