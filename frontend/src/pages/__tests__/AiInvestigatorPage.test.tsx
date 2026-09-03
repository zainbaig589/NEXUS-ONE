import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import AiInvestigatorPage from '@/pages/AiInvestigatorPage';
import { failFetch } from '@/test/apiMock';
import { INCIDENT_ID, incident, incidentSummary, investigation } from '@/test/fixtures';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body ?? {}), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

/**
 * Stateful mock: the persisted investigation 404s until POST /investigate
 * has been called, mirroring the real backend contract.
 */
function installStatefulMock() {
  const investigateCalls: Array<[string, RequestInit?]> = [];
  let investigationRun = false;
  const mock = vi.fn(async (url: string | URL, init?: RequestInit) => {
    const href = url.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    if (href.includes(`/api/v1/incidents/${INCIDENT_ID}/investigate`) && method === 'POST') {
      investigateCalls.push([href, init]);
      investigationRun = true;
      return json(investigation);
    }
    if (href.includes(`/api/v1/incidents/${INCIDENT_ID}/investigation`) && method === 'GET') {
      return investigationRun
        ? json(investigation)
        : json({ detail: 'No investigation has been run' }, 404);
    }
    if (href.includes(`/api/v1/incidents/${INCIDENT_ID}/summary`)) return json(incidentSummary);
    if (href.includes('/api/v1/incidents/')) return json([incident]);
    return json({ detail: `No mock for ${method} ${href}` }, 404);
  });
  vi.stubGlobal('fetch', mock);
  return { mock, investigateCalls };
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AiInvestigatorPage />
    </MemoryRouter>,
  );
}

describe('AiInvestigatorPage', () => {
  it('lists incidents and renders the evidence timeline with attack stages', async () => {
    installStatefulMock();

    renderPage();

    await waitFor(() => {
      expect(screen.getByTestId('investigator-incident-list')).toBeInTheDocument();
    });
    expect(screen.getByTestId('investigator-incident-option')).toHaveTextContent(
      'Correlated attack: brute force to exfiltration',
    );

    await waitFor(() => {
      expect(screen.getByTestId('investigator-timeline')).toBeInTheDocument();
    });
    const timeline = screen.getByTestId('investigator-timeline');
    expect(timeline.querySelectorAll('tbody tr')).toHaveLength(3);
    expect(timeline).toHaveTextContent('failed_login');
    expect(timeline).toHaveTextContent('privilege_escalation');
    expect(timeline).toHaveTextContent('data_transfer');
    // Source IPs render in the evidence panel meta-line, not the timeline table.
    expect(screen.getByTestId('investigator-evidence')).toHaveTextContent('185.220.101.5');

    const stages = screen.getByTestId('investigator-stages');
    expect(stages).toHaveTextContent('Credential Access');
    expect(stages).toHaveTextContent('Privilege Escalation');
    expect(stages).toHaveTextContent('Exfiltration');

    expect(screen.getByText(/No investigation run yet/i)).toBeInTheDocument();
  });

  it('runs the investigation on click and renders the DEMO MODE result', async () => {
    const user = userEvent.setup();
    const { investigateCalls } = installStatefulMock();

    renderPage();

    await waitFor(() => {
      expect(screen.getByTestId('investigate-button')).toBeInTheDocument();
    });

    await user.click(screen.getByTestId('investigate-button'));

    await waitFor(() => {
      expect(screen.getByTestId('investigation-summary')).toBeInTheDocument();
    });

    expect(investigateCalls).toHaveLength(1);
    expect(investigateCalls[0][0]).toContain(`/api/v1/incidents/${INCIDENT_ID}/investigate`);
    expect((investigateCalls[0][1]?.method ?? 'GET').toUpperCase()).toBe('POST');

    expect(screen.getByTestId('investigation-mode')).toHaveTextContent('DEMO MODE');
    expect(screen.getByTestId('investigator-mode')).toHaveTextContent('DEMO MODE');
    expect(screen.getByTestId('demo-notice')).toBeInTheDocument();
    expect(screen.getByTestId('investigation-summary')).toBeInTheDocument();
    expect(screen.getByText('Three correlated alerts spanning 12 minutes on host ws-042.')).toBeInTheDocument();
    expect(screen.getByTestId('investigation-section-tabs')).toBeInTheDocument();
  });

  it('shows a graceful error when the API is unreachable', async () => {
    failFetch();

    renderPage();

    await waitFor(() => {
      expect(screen.getByText(/Cannot reach the Nexus One API/i)).toBeInTheDocument();
    });
  });
});
