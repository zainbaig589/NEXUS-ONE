export default function StatusBadge({ status }: { status: string | null | undefined }) {
  const value = (status ?? 'unknown').toLowerCase().replace(/\s+/g, '_');
  const label = (status ?? 'unknown').replace(/_/g, ' ');
  const known = ['open', 'in_progress', 'investigating', 'resolved', 'closed'];
  const cls = known.includes(value) ? `badge badge-${value}` : 'badge badge-neutral';
  return <span className={cls}>{label}</span>;
}
