/**
 * The canonical multi-stage attack scenario used for demos and end-to-end
 * verification: SSH brute force → privilege escalation → data exfiltration.
 * Events are ingested through the real API endpoints.
 */

import type { EventCreate } from '@/types';

export function buildAttackScenarioEvents(): EventCreate[] {
  const now = Date.now();
  const at = (minutesOffset: number) =>
    new Date(now + minutesOffset * 60_000).toISOString();

  return [
    {
      source: 'auth-service',
      event_type: 'failed_login',
      severity: 'high',
      timestamp: at(0),
      payload: {
        src_ip: '185.220.101.5',
        user: 'admin',
        host: 'ws-042',
        failed_attempts: 6,
        action: 'ssh_login',
        outcome: 'failure',
      },
    },
    {
      source: 'auth-service',
      event_type: 'failed_login',
      severity: 'high',
      timestamp: at(2),
      payload: {
        src_ip: '185.220.101.5',
        user: 'admin',
        host: 'ws-042',
        failed_attempts: 9,
        action: 'ssh_login',
        outcome: 'failure',
      },
    },
    {
      source: 'auth-service',
      event_type: 'failed_login',
      severity: 'high',
      timestamp: at(4),
      payload: {
        src_ip: '185.220.101.5',
        user: 'admin',
        host: 'ws-042',
        failed_attempts: 11,
        action: 'ssh_login',
        outcome: 'failure',
      },
    },
    {
      source: 'auth-service',
      event_type: 'successful_login',
      severity: 'medium',
      timestamp: at(5),
      payload: {
        src_ip: '185.220.101.5',
        user: 'admin',
        host: 'ws-042',
        action: 'ssh_login',
        outcome: 'success',
      },
    },
    {
      source: 'iam',
      event_type: 'privilege_escalation',
      severity: 'critical',
      timestamp: at(7),
      payload: {
        src_ip: '185.220.101.5',
        user: 'admin',
        host: 'ws-042',
        old_role: 'viewer',
        new_role: 'root',
        method: 'sudo',
      },
    },
    {
      source: 'netflow',
      event_type: 'data_transfer',
      severity: 'critical',
      timestamp: at(12),
      payload: {
        src_ip: '185.220.101.5',
        dst_ip: '198.51.100.7',
        user: 'admin',
        host: 'ws-042',
        bytes_transferred: 2147483648,
        protocol: 'https',
      },
    },
  ];
}
