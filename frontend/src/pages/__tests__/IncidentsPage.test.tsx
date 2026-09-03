import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import IncidentsPage from '@/pages/IncidentsPage';
import { installFetchMock } from '@/test/apiMock';
import { alerts, incident } from '@/test/fixtures';
import type { Incident } from '@/types';

const lowIncident: Incident = {
  ...incident,
  id: 'inc-0002-low',
  title: 'Low-severity policy violation',
  severity: 'low',
  risk_score: 12.5,
  risk_level: 'LOW',
  alert_count: 1,
  alert_ids: ['alert-1'],
};

function renderList() {
  return render(
    <MemoryRouter initialEntries={['/incidents']}>
      <IncidentsPage />
    </MemoryRouter>,
  );
}

describe('IncidentsPage', () => {
  it('loads incidents from the API and renders them in the table', async () => {
    installFetchMock({
      '/api/v1/incidents/': { body: [incident, lowIncident] },
      '/api/v1/incidents/inc-0001-abcd1234/alerts': { body: alerts },
      '/api/v1/incidents/inc-0002-low/alerts': { body: alerts.slice(0, 1) },
    });

    renderList();

    await waitFor(() => {
      expect(screen.getAllByTestId('incident-row')).toHaveLength(2);
    });
    expect(screen.getByText('Correlated attack: brute force to exfiltration')).toBeInTheDocument();
    expect(screen.getByText('Low-severity policy violation')).toBeInTheDocument();
    expect(screen.getByText('62.8')).toBeInTheDocument();
  });

  it('filters incidents by severity client-side', async () => {
    const user = userEvent.setup();
    installFetchMock({
      '/api/v1/incidents/': { body: [incident, lowIncident] },
    });

    renderList();

    await waitFor(() => {
      expect(screen.getAllByTestId('incident-row')).toHaveLength(2);
    });

    await user.selectOptions(screen.getByTestId('severity-filter'), 'critical');

    await waitFor(() => {
      expect(screen.getAllByTestId('incident-row')).toHaveLength(1);
    });
    expect(screen.getByText('Correlated attack: brute force to exfiltration')).toBeInTheDocument();
    expect(screen.queryByText('Low-severity policy violation')).not.toBeInTheDocument();
  });

  it('sorts incidents by risk score when the column header is clicked', async () => {
    const user = userEvent.setup();
    installFetchMock({
      '/api/v1/incidents/': { body: [incident, lowIncident] },
    });

    renderList();

    await waitFor(() => {
      expect(screen.getAllByTestId('incident-row')).toHaveLength(2);
    });

    await user.click(screen.getByRole('columnheader', { name: /Risk/i }));

    const rows = screen.getAllByTestId('incident-row');
    expect(rows[0]).toHaveTextContent('Correlated attack');
    expect(rows[1]).toHaveTextContent('Low-severity policy violation');
  });
});
