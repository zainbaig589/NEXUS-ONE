import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import AssetsPage from '@/pages/AssetsPage';
import { installFetchMock, failFetch } from '@/test/apiMock';
import { alerts, events, incident } from '@/test/fixtures';

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
      <AssetsPage />
    </MemoryRouter>,
  );
}

describe('AssetsPage', () => {
  it('discovers assets in telemetry with event, alert, and incident counts', async () => {
    installRoutes();

    renderPage();

    await waitFor(() => {
      expect(screen.getAllByTestId('asset-row')).toHaveLength(7);
    });

    const rows = screen.getAllByTestId<HTMLTableRowElement>('asset-row');
    const byAsset = new Map(
      rows.map((row) => [`${row.cells[1].textContent}:${row.cells[0].textContent}`, row]),
    );
    expect([...byAsset.keys()].sort()).toEqual([
      'Destination IP:198.51.100.7',
      'Endpoint:auth-service',
      'Endpoint:iam',
      'Endpoint:netflow',
      'Host:ws-042',
      'Source IP:185.220.101.5',
      'User:admin',
    ]);

    // ws-042 appears in every event and every one of its alerts fired.
    const ws = byAsset.get('Host:ws-042');
    expect(ws?.cells[2].textContent).toBe('3');
    expect(ws?.cells[3].textContent).toBe('3');
    expect(ws?.cells[4].textContent).toContain('1');

    // 198.51.100.7 only appears in the exfiltration event.
    const dstIp = byAsset.get('Destination IP:198.51.100.7');
    expect(dstIp?.cells[2].textContent).toBe('1');
    expect(dstIp?.cells[3].textContent).toBe('1');
    expect(dstIp).toHaveTextContent('inc-0001');

    const summary = screen.getByTestId('assets-summary');
    expect(summary).toHaveTextContent('Hosts:');
    expect(summary).toHaveTextContent('Users:');
    expect(summary).toHaveTextContent('Endpoints:');
  });

  it('sorts incident-linked assets first', async () => {
    installRoutes();

    renderPage();

    await waitFor(() => {
      expect(screen.getAllByTestId('asset-row')).toHaveLength(7);
    });
    const rows = screen.getAllByTestId<HTMLTableRowElement>('asset-row');
    // All four incident-linked assets precede the unlinked endpoints.
    const firstFour = rows.slice(0, 4).map((row) => row.cells[0].textContent);
    expect(firstFour).toEqual(
      expect.arrayContaining(['ws-042', 'admin', '185.220.101.5', '198.51.100.7']),
    );
    expect(rows[4].cells[1].textContent).toBe('Endpoint');
  });

  it('filters assets by type', async () => {
    const user = userEvent.setup();
    installRoutes();

    renderPage();

    await waitFor(() => {
      expect(screen.getAllByTestId('asset-row')).toHaveLength(7);
    });

    await user.selectOptions(screen.getByTestId('assets-type-filter'), 'Host');
    await waitFor(() => {
      expect(screen.getAllByTestId('asset-row')).toHaveLength(1);
    });
    expect((screen.getAllByTestId('asset-row')[0] as HTMLTableRowElement).cells[0].textContent).toBe('ws-042');

    await user.selectOptions(screen.getByTestId('assets-type-filter'), 'Endpoint');
    await waitFor(() => {
      expect(screen.getAllByTestId('asset-row')).toHaveLength(3);
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
