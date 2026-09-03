import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import AnalyticsPage from '@/pages/AnalyticsPage';
import { installFetchMock, failFetch, type RouteTable } from '@/test/apiMock';
import { alerts, events, incident, mlStatus } from '@/test/fixtures';

function installRoutes(overrides: RouteTable = {}): ReturnType<typeof installFetchMock> {
  return installFetchMock({
    '/api/v1/incidents/': { body: [incident] },
    '/api/v1/alerts/': { body: alerts },
    '/api/v1/events/': { body: events },
    '/api/v1/ml/status': { body: mlStatus },
    ...overrides,
  });
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AnalyticsPage />
    </MemoryRouter>,
  );
}

describe('AnalyticsPage', () => {
  it('renders every analytics panel from real API data', async () => {
    installRoutes();

    renderPage();

    await waitFor(() => {
      expect(screen.getByTestId('analytics-ml')).toBeInTheDocument();
    });

    expect(screen.getByTestId('analytics-incident-severity')).toHaveTextContent('1 incidents');
    expect(screen.getByTestId('analytics-alert-distribution')).toHaveTextContent(
      '3 alerts by severity',
    );

    const detection = screen.getByTestId('analytics-detection-methods');
    expect(detection).toHaveTextContent('RULE');
    expect(detection).toHaveTextContent('ML');
    expect(detection).toHaveTextContent('2');
    expect(detection).toHaveTextContent('1');

    const risk = screen.getByTestId('analytics-risk-distribution');
    expect(risk).toHaveTextContent('HIGH');
    expect(risk).toHaveTextContent('1 incident');

    const stages = screen.getByTestId('analytics-attack-stages');
    expect(stages).toHaveTextContent('Credential Access');
    expect(stages).toHaveTextContent('Privilege Escalation');
    expect(stages).toHaveTextContent('Exfiltration');

    const types = screen.getByTestId('analytics-attack-types');
    expect(types).toHaveTextContent('failed_login');
    expect(types).toHaveTextContent('privilege_escalation');
    expect(types).toHaveTextContent('data_transfer');
    expect(types).toHaveTextContent('33%');

    const ml = screen.getByTestId('analytics-ml');
    expect(ml).toHaveTextContent('isolation forest');
    expect(ml).toHaveTextContent('1200');
    expect(ml).toHaveTextContent('0.62');
    expect(ml).toHaveTextContent('YES');
  });

  it('shows empty states instead of fabricated figures when there is no data', async () => {
    installRoutes({
      '/api/v1/incidents/': { body: [] },
      '/api/v1/alerts/': { body: [] },
      '/api/v1/events/': { body: [] },
    });

    renderPage();

    await waitFor(() => {
      expect(screen.getAllByText('No incidents yet').length).toBeGreaterThanOrEqual(2);
    });
    expect(screen.getByText('No alerts yet')).toBeInTheDocument();
    expect(screen.getByText('No detections yet')).toBeInTheDocument();
    expect(screen.getByText('No attack stages observed')).toBeInTheDocument();
    expect(screen.getByText('No events yet')).toBeInTheDocument();
  });

  it('shows a graceful error when the API is unreachable', async () => {
    failFetch();

    renderPage();

    await waitFor(() => {
      expect(screen.getByText(/Cannot reach the Nexus One API/i)).toBeInTheDocument();
    });
  });
});
