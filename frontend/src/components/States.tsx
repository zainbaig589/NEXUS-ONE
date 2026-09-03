export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="loading" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="empty-state">
      <div className="empty-icon" aria-hidden="true">◇</div>
      <div>{title}</div>
      {hint ? <div style={{ fontSize: 12, marginTop: 4 }}>{hint}</div> : null}
    </div>
  );
}

export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="error-banner" role="alert" data-testid="error-banner">
      <span aria-hidden="true">⚠</span>
      <span>{message}</span>
      {onRetry ? (
        <button type="button" className="btn btn-sm retry-btn" onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </div>
  );
}
