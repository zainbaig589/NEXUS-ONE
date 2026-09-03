import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import IncidentDetailPage from '@/pages/IncidentDetailPage';
import { installFetchMock, failFetch, type RouteTable } from '@/test/apiMock';
import {
  INCIDENT_ID,
  alerts,
  incidentSummary,
  investigation,
  recommendations,
  report,
} from '@/test/fixtures';

function baseRoutes(overrides: RouteTable = {}): RouteTable {
  const base = `/api/v1/incidents/${INCIDENT_ID}`;
  return {
    [`${base}/summary`]: { body: incidentSummary },
    [`${base}/alerts`]: { body: alerts },
    [`${base}/investigation`]: { status: 404, body: { detail: 'No investigation has been run' } },
    [`${base}/recommendations`]: { body: recommendations },
    [`${base}/report`]: { body: report },
    ...overrides,
  };
}

function renderDetail() {
  return render(
    <MemoryRouter initialEntries={[`/incidents/${INCIDENT_ID}`]}>
      <Routes>
        <Route path="/incidents/:incidentId" element={<IncidentDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('IncidentDetailPage', () => {
  it('loads the incident header, risk score, and explanation from the API', async () => {
    installFetchMock(baseRoutes());

    renderDetail();

    await waitFor(() => {
      expect(screen.getByTestId('incident-header')).toBeInTheDocument();
    });
    expect(screen.getByText('Correlated attack: brute force to exfiltration')).toBeInTheDocument();
    expect(screen.getByTestId('risk-score')).toHaveTextContent('62.8');
    expect(screen.getByTestId('risk-factors')).toHaveTextContent(/Critical-severity alerts present/);
    expect(screen.getByTestId('risk-explanation')).toHaveTextContent(/Base 40 for critical/);
  });

  it('renders the attack timeline chronologically with event details', async () => {
    installFetchMock(baseRoutes());

    const { container } = renderDetail();

    await waitFor(() => {
      expect(container.querySelectorAll('.timeline-entry')).toHaveLength(3);
    });
    const entries = container.querySelectorAll('.timeline-entry');
    expect(entries[0]).toHaveTextContent('failed_login');
    expect(entries[1]).toHaveTextContent('privilege_escalation');
    expect(entries[2]).toHaveTextContent('data_transfer');
    expect(entries[0]).toHaveTextContent('admin');
    expect(entries[0]).toHaveTextContent('ws-042');
    expect(entries[2]).toHaveTextContent('198.51.100.7');
  });

  it('shows only the attack stages returned by the backend', async () => {
    installFetchMock(baseRoutes());

    renderDetail();

    await waitFor(() => {
      expect(screen.getByTestId('stage-list')).toBeInTheDocument();
    });
    const stages = screen.getAllByText(/^(Credential Access|Privilege Escalation|Exfiltration)$/);
    expect(stages.length).toBeGreaterThanOrEqual(3);
    expect(screen.queryByText('Initial Access')).not.toBeInTheDocument();
  });

  it('renders the correlated alerts with evidence IDs and detection methods', async () => {
    installFetchMock(baseRoutes());

    renderDetail();

    await waitFor(() => {
      expect(screen.getByTestId('alerts-table')).toBeInTheDocument();
    });
    expect(screen.getByText('Multiple Failed Logins')).toBeInTheDocument();
    expect(screen.getByText('Large Data Transfer')).toBeInTheDocument();
    expect(screen.getAllByText('ML').length).toBeGreaterThan(0);
    expect(screen.getAllByText('alert-alert-1').length).toBeGreaterThan(0);
    expect(screen.getAllByText('event-event-3').length).toBeGreaterThan(0);
  });

  it('calls the investigate endpoint on click and renders the results with the DEMO badge', async () => {
    const user = userEvent.setup();
    const base = `/api/v1/incidents/${INCIDENT_ID}`;
    let investigationRun = false;
    const investigateCalls: Array<[string, RequestInit?]> = [];

    const json = (body: unknown, status = 200) =>
      new Response(JSON.stringify(body ?? {}), {
        status,
        headers: { 'Content-Type': 'application/json' },
      });

    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const href = url.toString();
      const method = (init?.method ?? 'GET').toUpperCase();
      if (href.includes(`${base}/investigate`) && method === 'POST') {
        investigateCalls.push([href, init]);
        investigationRun = true;
        return json(investigation);
      }
      if (href.includes(`${base}/investigation`) && method === 'GET') {
        return investigationRun
          ? json(investigation)
          : json({ detail: 'No investigation has been run' }, 404);
      }
      if (href.includes(`${base}/summary`)) return json(incidentSummary);
      if (href.includes(`${base}/alerts`)) return json(alerts);
      if (href.includes(`${base}/recommendations`)) return json(recommendations);
      if (href.includes(`${base}/report`)) return json(report);
      return json({ detail: `No mock for ${method} ${href}` }, 404);
    });
    vi.stubGlobal('fetch', fetchMock);

    renderDetail();

    await waitFor(() => {
      expect(screen.getByTestId('investigate-button')).toBeInTheDocument();
    });
    expect(screen.getByText(/No investigation run yet/i)).toBeInTheDocument();

    await user.click(screen.getByTestId('investigate-button'));

    await waitFor(() => {
      expect(screen.getByTestId('investigation-summary')).toBeInTheDocument();
    });

    expect(investigateCalls).toHaveLength(1);
    expect(investigateCalls[0][0]).toContain(`/api/v1/incidents/${INCIDENT_ID}/investigate`);
    expect((investigateCalls[0][1]?.method ?? 'GET').toUpperCase()).toBe('POST');

    expect(screen.getByTestId('investigation-mode')).toHaveTextContent('DEMO MODE');
    expect(screen.getByTestId('demo-notice')).toBeInTheDocument();
    expect(screen.getByTestId('investigation-summary')).toBeInTheDocument();
    expect(screen.getByText('Three correlated alerts spanning 12 minutes on host ws-042.')).toBeInTheDocument();
    expect(screen.getByTestId('investigation-section-tabs')).toBeInTheDocument();
  });

  it('renders response recommendations with advisory labelling', async () => {
    installFetchMock(baseRoutes());

    renderDetail();

    await waitFor(() => {
      expect(screen.getAllByTestId('recommendation-card').length).toBe(2);
    });
    expect(screen.getByText('Reset compromised account credentials')).toBeInTheDocument();
    expect(screen.getByText('Isolate affected endpoint')).toBeInTheDocument();
    expect(screen.getByText('ADVISORY — REQUIRES ANALYST APPROVAL')).toBeInTheDocument();
    expect(
      screen.getByText('Critical priority because the incident is HIGH risk (62.8/100).'),
    ).toBeInTheDocument();
  });

  it('loads and renders the persisted incident report', async () => {
    installFetchMock(baseRoutes());

    renderDetail();

    await waitFor(() => {
      expect(screen.getByTestId('report-summary')).toBeInTheDocument();
    });
    expect(
      screen.getByText('Three alerts over 12 minutes indicating a compromised admin account.'),
    ).toBeInTheDocument();
    expect(screen.getAllByText('alert-alert-1').length).toBeGreaterThan(0);
  });

  it('shows a graceful error when the API is unreachable', async () => {
    failFetch();

    renderDetail();

    await waitFor(() => {
      expect(screen.getByTestId('error-banner')).toBeInTheDocument();
    });
    expect(screen.getByText(/Cannot reach the Nexus One API/i)).toBeInTheDocument();
  });
});
