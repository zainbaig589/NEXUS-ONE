import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import DashboardPage from '@/pages/DashboardPage';
import { installFetchMock, failFetch } from '@/test/apiMock';
import { alerts, health, incident } from '@/test/fixtures';

function renderDashboard() {
  return render(
    <MemoryRouter initialEntries={['/']}>
      <DashboardPage />
    </MemoryRouter>,
  );
}

describe('DashboardPage', () => {
  it('loads and shows metric cards from the real API', async () => {
    installFetchMock({
      '/health': { body: health },
      '/api/v1/incidents/': { body: [incident] },
      '/api/v1/alerts/': { body: alerts },
    });

    renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId('metric-total-incidents')).toHaveTextContent('1');
    });
    expect(screen.getByTestId('metric-critical-incidents')).toHaveTextContent('1');
    expect(screen.getByTestId('metric-high-risk')).toHaveTextContent('1');
    expect(screen.getByTestId('metric-active-alerts')).toHaveTextContent('3');
    expect(screen.getByTestId('metric-ml-anomalies')).toHaveTextContent('1');
  });

  it('shows the recent incidents table with API data', async () => {
    installFetchMock({
      '/health': { body: health },
      '/api/v1/incidents/': { body: [incident] },
      '/api/v1/alerts/': { body: alerts },
    });

    renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId('recent-incidents')).toBeInTheDocument();
    });
    expect(screen.getByText('Correlated attack: brute force to exfiltration')).toBeInTheDocument();
  });

  it('renders severity and detection-method chart panels', async () => {
    installFetchMock({
      '/health': { body: health },
      '/api/v1/incidents/': { body: [incident] },
      '/api/v1/alerts/': { body: alerts },
    });

    renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId('severity-chart')).toBeInTheDocument();
    });
    expect(screen.getByTestId('detection-chart')).toBeInTheDocument();
  });

  it('shows an error banner when the backend is unreachable', async () => {
    failFetch();

    renderDashboard();

    await waitFor(() => {
      expect(screen.getAllByTestId('error-banner').length).toBeGreaterThan(0);
    });
    expect(
      screen.getAllByText(/Cannot reach the Nexus One API/i).length,
    ).toBeGreaterThan(0);
  });
});
