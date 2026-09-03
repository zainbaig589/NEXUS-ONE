import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import ReportsPage from '@/pages/ReportsPage';
import { failFetch } from '@/test/apiMock';
import { INCIDENT_ID, incident, report } from '@/test/fixtures';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body ?? {}), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

/**
 * Stateful mock: the persisted report 404s until POST /report has been
 * called, mirroring the real backend contract.
 */
function installStatefulMock() {
  const reportCalls: Array<[string, RequestInit?]> = [];
  let reportGenerated = false;
  const mock = vi.fn(async (url: string | URL, init?: RequestInit) => {
    const href = url.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    if (href.includes(`/api/v1/incidents/${INCIDENT_ID}/report`)) {
      if (method === 'POST') {
        reportCalls.push([href, init]);
        reportGenerated = true;
        return json(report);
      }
      return reportGenerated ? json(report) : json({ detail: 'No report generated' }, 404);
    }
    if (href.includes('/api/v1/incidents/')) return json([incident]);
    return json({ detail: `No mock for ${method} ${href}` }, 404);
  });
  vi.stubGlobal('fetch', mock);
  return { reportCalls };
}

function renderPage() {
  return render(
    <MemoryRouter>
      <ReportsPage />
    </MemoryRouter>,
  );
}

describe('ReportsPage', () => {
  it('lists incidents and shows the empty report state before generation', async () => {
    installStatefulMock();

    renderPage();

    await waitFor(() => {
      expect(screen.getAllByTestId('report-incident-row')).toHaveLength(1);
    });
    expect(screen.getByTestId('reports-incident-table')).toHaveTextContent(
      'Correlated attack: brute force to exfiltration',
    );
    // The report GET 404s asynchronously before the empty state appears.
    await waitFor(() => {
      expect(screen.getByText(/No report generated for this incident/i)).toBeInTheDocument();
    });
  });

  it('generates the report on click and renders the persisted report body', async () => {
    const user = userEvent.setup();
    const { reportCalls } = installStatefulMock();

    renderPage();

    await waitFor(() => {
      expect(screen.getByTestId('generate-report-row-button')).toBeInTheDocument();
    });

    await user.click(screen.getByTestId('generate-report-row-button'));

    await waitFor(() => {
      expect(screen.getByTestId('report-summary')).toBeInTheDocument();
    });

    expect(reportCalls).toHaveLength(1);
    expect(reportCalls[0][0]).toContain(`/api/v1/incidents/${INCIDENT_ID}/report`);
    expect((reportCalls[0][1]?.method ?? 'GET').toUpperCase()).toBe('POST');

    expect(screen.getByTestId('report-summary')).toHaveTextContent(
      'Three alerts over 12 minutes indicating a compromised admin account.',
    );

    const info = screen.getByTestId('report-incident-info');
    expect(info).toHaveTextContent(INCIDENT_ID);
    expect(info).toHaveTextContent('62.8');
    expect(info).toHaveTextContent('HIGH');
    expect(info).toHaveTextContent('0.87');

    const stages = screen.getByTestId('report-stages');
    expect(stages).toHaveTextContent('Credential Access');
    expect(stages).toHaveTextContent('Privilege Escalation');
    expect(stages).toHaveTextContent('Exfiltration');

    expect(screen.getByTestId('report-evidence')).toHaveTextContent('alert-alert-1');
    expect(screen.getByTestId('report-evidence')).toHaveTextContent('event-event-3');

    const ai = screen.getByTestId('report-ai-investigation');
    expect(ai).toHaveTextContent('demo');
    expect(ai).toHaveTextContent('82%');
    expect(ai).toHaveTextContent(
      'Consistent with credential compromise followed by data exfiltration.',
    );

    const recs = screen.getByTestId('report-recommendations');
    expect(recs).toHaveTextContent('Reset compromised account credentials');
    expect(recs).toHaveTextContent('Isolate affected endpoint');
    expect(recs).toHaveTextContent('All actions require analyst approval.');

    expect(screen.getByText('DEMO MODE')).toBeInTheDocument();
    expect(screen.getByText('Generated')).toBeInTheDocument();
  });

  it('shows a graceful error when the API is unreachable', async () => {
    failFetch();

    renderPage();

    await waitFor(() => {
      expect(screen.getByText(/Cannot reach the Nexus One API/i)).toBeInTheDocument();
    });
  });
});
