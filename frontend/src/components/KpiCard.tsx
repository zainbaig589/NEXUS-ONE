import type { CSSProperties, ReactNode } from 'react';

function sparkPoints(values: number[]): { line: string; fill: string } {
  const width = 100;
  const height = 28;
  const max = Math.max(...values, 1);
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const coords = values.map((value, i) => {
    const x = i * step;
    const y = height - 3 - (value / max) * (height - 8);
    return [x, y] as const;
  });
  const line = coords.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
  const fill = `0,${height} ${line} ${width},${height}`;
  return { line, fill };
}

/**
 * Glassmorphic KPI tile: large value, tinted icon chip, optional sparkline.
 * The sparkline is only rendered when the caller passes real time-bucketed
 * counts — never a fabricated trend.
 */
export default function KpiCard({
  label,
  value,
  hint,
  icon,
  color,
  testId,
  spark,
}: {
  label: string;
  value: number | string;
  hint: string;
  icon: ReactNode;
  color: string;
  testId?: string;
  spark?: number[] | null;
}) {
  const points = spark && spark.length > 1 ? sparkPoints(spark) : null;
  return (
    <div
      className="kpi-card"
      style={{ '--kpi-color': color } as CSSProperties}
      data-testid={testId}
    >
      <div className="kpi-head">
        <span className="kpi-icon" aria-hidden="true">
          {icon}
        </span>
        <span className="kpi-label">{label}</span>
      </div>
      <div className="kpi-value">{value}</div>
      {points ? (
        <svg className="kpi-spark" viewBox="0 0 100 28" preserveAspectRatio="none" aria-hidden="true">
          <polygon points={points.fill} />
          <polyline points={points.line} />
        </svg>
      ) : null}
      <div className="kpi-hint">{hint}</div>
    </div>
  );
}
