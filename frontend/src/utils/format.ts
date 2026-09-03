import type { Severity } from '@/types';

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

const RISK_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function severityRank(severity: string | null | undefined): number {
  return SEVERITY_RANK[(severity ?? 'info').toLowerCase()] ?? 0;
}

export function riskRank(level: string | null | undefined): number {
  return RISK_RANK[(level ?? 'LOW').toUpperCase()] ?? 0;
}

export function normalizeSeverity(severity: string | null | undefined): Severity {
  const value = (severity ?? 'info').toLowerCase();
  return (SEVERITY_ORDER as string[]).includes(value) ? (value as Severity) : 'info';
}

export function severityLabel(severity: string | null | undefined): string {
  return normalizeSeverity(severity).toUpperCase();
}

export function shortId(id: string | null | undefined, length = 8): string {
  if (!id) return '—';
  return id.length <= length ? id : id.slice(0, length);
}

export function formatDateTime(iso: string | Date | null | undefined): string {
  if (iso == null || iso === '') return '—';
  const date = iso instanceof Date ? iso : new Date(iso);
  if (Number.isNaN(date.getTime())) return String(iso);
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || Number.isNaN(seconds)) return '—';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const minutes = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  if (minutes < 60) return secs > 0 ? `${minutes}m ${secs}s` : `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return remainingMinutes > 0 ? `${hours}h ${remainingMinutes}m` : `${hours}h`;
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null || Number.isNaN(bytes)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 100 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

export function formatConfidence(confidence: number | null | undefined): string {
  if (confidence == null) return '—';
  return `${Math.round(confidence * 100)}%`;
}

export function riskLevelColor(level: string | null | undefined): string {
  switch ((level ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'var(--critical)';
    case 'HIGH':
      return 'var(--high)';
    case 'MEDIUM':
      return 'var(--medium)';
    default:
      return 'var(--low)';
  }
}

/** Strips the "Potential stage: " prefix the backend adds to stage labels. */
export function stageLabel(stage: string | null | undefined): string {
  if (!stage) return '';
  return stage.replace(/^Potential stage:\s*/i, '');
}
