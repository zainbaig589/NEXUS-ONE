export default function EvidenceIds({ ids, emptyLabel }: { ids: string[]; emptyLabel?: string }) {
  if (!ids || ids.length === 0) {
    return emptyLabel ? <span style={{ color: 'var(--text-dim)' }}>{emptyLabel}</span> : null;
  }
  return (
    <span className="evidence-ids">
      {ids.map((id) => (
        <span key={id} className="evidence-id mono" title={`Evidence citation: ${id}`}>
          {id}
        </span>
      ))}
    </span>
  );
}
