import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import ThreatIntelPage from '@/pages/ThreatIntelPage';
import { installFetchMock, failFetch } from '@/test/apiMock';
import { INCIDENT_ID, alerts, events, incident } from '@/test/fixtures';

function installRoutes(): ReturnType<typeof installFetchMock> {
  return installFetchMock({
    '/api/v1/incidents/': { body: [incident] },
    '/api/v1/alerts/': { body: alerts },
    '/api/v1/events/': { body: events },
  });
}

function renderPage() {
  return render(
    <MemoryRouter>
      <ThreatIntelPage />
    </MemoryRouter>,
  );
}

describe('ThreatIntelPage', () => {
  it('derives indicators from ingested telemetry with alert counts', async () => {
    installRoutes();

    renderPage();

    await waitFor(() => {
      expect(screen.getAllByTestId('intel-row')).toHaveLength(4);
    });

    const rows = screen.getAllByTestId<HTMLTableRowElement>('intel-row');
    const byIndicator = new Map(
      rows.map((row) => [row.cells[0].textContent ?? '', row] as const),
    );
    expect([...byIndicator.keys()].sort()).toEqual([
      '185.220.101.5',
      '198.51.100.7',
      'admin',
      'ws-042',
    ]);

    expect(byIndicator.get('185.220.101.5')?.cells[1].textContent).toBe('IP Address');
    expect(byIndicator.get('198.51.100.7')?.cells[1].textContent).toBe('IP Address');
    expect(byIndicator.get('ws-042')?.cells[1].textContent).toBe('Host');
    expect(byIndicator.get('admin')?.cells[1].textContent).toBe('User');

    // 185.220.101.5 appears in every event, so all three alerts reference it.
    expect(
      byIndicator.get('185.220.101.5')?.cells[4].querySelector('b')?.textContent,
    ).toBe('3');
    // 198.51.100.7 only appears in the exfiltration event.
    expect(
      byIndicator.get('198.51.100.7')?.cells[4].querySelector('b')?.textContent,
    ).toBe('1');

    const summary = screen.getByTestId('intel-summary');
    expect(summary).toHaveTextContent('Indicators:');
    expect(summary).toHaveTextContent('With related alerts:');
    expect(summary).toHaveTextContent('With related incidents:');
  });

  it('links every related indicator to its correlated incident', async () => {
    installRoutes();

    renderPage();

    await waitFor(() => {
      expect(screen.getAllByTestId('intel-row')).toHaveLength(4);
    });
    const links = screen.getAllByRole('link', { name: 'inc-0001' });
    expect(links).toHaveLength(4);
    for (const link of links) {
      expect(link).toHaveAttribute('href', `/incidents/${INCIDENT_ID}`);
    }
  });

  it('filters indicators by type', async () => {
    const user = userEvent.setup();
    installRoutes();

    renderPage();

    await waitFor(() => {
      expect(screen.getAllByTestId('intel-row')).toHaveLength(4);
    });

    await user.selectOptions(screen.getByTestId('intel-type-filter'), 'IP Address');
    await waitFor(() => {
      expect(screen.getAllByTestId('intel-row')).toHaveLength(2);
    });

    await user.selectOptions(screen.getByTestId('intel-type-filter'), 'User');
    await waitFor(() => {
      expect(screen.getAllByTestId('intel-row')).toHaveLength(1);
    });
  });

  it('shows a graceful error when the API is unreachable', async () => {
    failFetch();

    renderPage();

    await waitFor(() => {
      expect(screen.getByText(/Cannot reach the Nexus One API/i)).toBeInTheDocument();
    });
  });
});
