import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import AlertsPage from '@/pages/AlertsPage';
import { installFetchMock, failFetch, type RouteTable } from '@/test/apiMock';
import { alerts } from '@/test/fixtures';

function installRoutes(overrides: RouteTable = {}): ReturnType<typeof installFetchMock> {
  return installFetchMock({
    '/api/v1/alerts/': { body: alerts },
    ...overrides,
  });
}

describe('AlertsPage', () => {
  it('renders alerts with rule names, sources, and the severity summary', async () => {
    installRoutes();

    render(<AlertsPage />);

    await waitFor(() => {
      expect(screen.getAllByTestId('alert-row')).toHaveLength(3);
    });
    expect(screen.getByText('Multiple Failed Logins')).toBeInTheDocument();
    expect(screen.getByText('Privilege Escalation via Sudo')).toBeInTheDocument();
    expect(screen.getByText('Large Data Transfer')).toBeInTheDocument();
    expect(
      screen.getByText('11 failed SSH logins for admin from 185.220.101.5'),
    ).toBeInTheDocument();

    const summary = screen.getByTestId('alerts-summary');
    expect(summary).toHaveTextContent('Rule engine:');
    expect(summary).toHaveTextContent('ML anomalies:');
    expect(summary.querySelectorAll('b')[0].textContent).toBe('2');
    expect(summary.querySelectorAll('b')[1].textContent).toBe('1');
  });

  it('refetches from the API when severity and status filters change', async () => {
    const user = userEvent.setup();
    const { mock } = installRoutes();

    render(<AlertsPage />);

    await waitFor(() => {
      expect(screen.getAllByTestId('alert-row')).toHaveLength(3);
    });

    await user.selectOptions(screen.getByTestId('alerts-severity-filter'), 'critical');
    await waitFor(() => {
      expect(
        mock.mock.calls.some(([url]) => url.toString().includes('severity=critical')),
      ).toBe(true);
    });

    await user.selectOptions(screen.getByTestId('alerts-status-filter'), 'new');
    await waitFor(() => {
      expect(
        mock.mock.calls.some(([url]) => url.toString().includes('status_filter=new')),
      ).toBe(true);
    });
  });

  it('shows a graceful empty state when no alerts exist', async () => {
    installRoutes({ '/api/v1/alerts/': { body: [] } });

    render(<AlertsPage />);

    await waitFor(() => {
      expect(screen.getByText('No alerts found')).toBeInTheDocument();
    });
  });

  it('shows a graceful error when the API is unreachable', async () => {
    failFetch();

    render(<AlertsPage />);

    await waitFor(() => {
      expect(screen.getByText(/Cannot reach the Nexus One API/i)).toBeInTheDocument();
    });
  });
});
