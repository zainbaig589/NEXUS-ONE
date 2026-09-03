import { normalizeSeverity, severityLabel } from '@/utils/format';
import type { Severity } from '@/types';

export default function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  const level = normalizeSeverity(severity);
  return (
    <span className={`badge badge-${level}`} data-severity={level}>
      {severityLabel(level)}
    </span>
  );
}

export function severityColor(level: Severity): string {
  switch (level) {
    case 'critical':
      return 'var(--critical)';
    case 'high':
      return 'var(--high)';
    case 'medium':
      return 'var(--medium)';
    case 'low':
      return 'var(--low)';
    default:
      return 'var(--info)';
  }
}
