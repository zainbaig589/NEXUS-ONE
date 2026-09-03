import type { Health } from '@/types';

export default function SystemStatus({ health }: { health: Health | null }) {
  const ok = health?.status === 'healthy';
  return (
    <div
      className={`health ${ok ? 'health-ok' : 'health-down'}`}
      data-testid="system-status"
      title={
        health
          ? `${health.app_name} v${health.version} · ${health.environment} · db ${health.database}`
          : 'Backend unreachable'
      }
    >
      <span className="health-dot" aria-hidden="true" />
      {health ? (ok ? 'System Secure' : 'System Degraded') : 'System Offline'}
    </div>
  );
}
