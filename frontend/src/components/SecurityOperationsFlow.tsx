/**
 * SECURITY OPERATIONS FLOW — the signature dashboard visualization.
 *
 * Telemetry sources (real event counts from /api/v1/events/) stream through a
 * multi-layer perspective "cyber tunnel" (outer + inner hulls, breathing
 * rings, glowing junction nodes, an expanding engine pulse and animated
 * binary particles) into the correlation engine core, and out to detection
 * outputs (real incident/alert counts). Below the tunnel, the SOC lifecycle
 * pipeline reflects real data presence. No invented numbers: every count
 * comes from the API payloads.
 */

import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  IconAlerts,
  IconCloud,
  IconCpu,
  IconDatabase,
  IconEndpoint,
  IconIdentity,
  IconIncidents,
  IconInvestigator,
  IconLogs,
  IconNetwork,
  IconReports,
  IconZap,
} from '@/components/icons';
import type { Alert, Incident, SecurityEvent } from '@/types';

type SourceKey = 'identity' | 'endpoints' | 'network' | 'cloud' | 'logs';

type SourceDef = { key: SourceKey; label: string; icon: typeof IconLogs; keywords: string[] };

/** Keyword map from real backend event sources to the five display channels. */
const SOURCES: SourceDef[] = [
  {
    key: 'identity',
    label: 'IDENTITY',
    icon: IconIdentity,
    keywords: ['auth', 'iam', 'identity', 'vpn', 'login', 'directory'],
  },
  {
    key: 'endpoints',
    label: 'ENDPOINTS',
    icon: IconEndpoint,
    keywords: ['workstation', 'endpoint', 'edr', 'host', 'laptop', 'process'],
  },
  {
    key: 'network',
    label: 'NETWORK',
    icon: IconNetwork,
    keywords: ['firewall', 'netflow', 'ids', 'network', 'dns', 'proxy', 'traffic'],
  },
  {
    key: 'cloud',
    label: 'CLOUD',
    icon: IconCloud,
    keywords: ['cloud', 'aws', 'azure', 'gcp', 's3', 'k8s'],
  },
  {
    key: 'logs',
    label: 'LOGS',
    icon: IconLogs,
    keywords: ['log', 'audit', 'server', 'sys', 'app', 'db', 'os', 'kernel'],
  },
];

function classifySource(source: string | null | undefined): SourceKey {
  const value = (source ?? '').toLowerCase();
  for (const def of SOURCES) {
    if (def.keywords.some((keyword) => value.includes(keyword))) return def.key;
  }
  return 'logs';
}

const PARTICLE_BITS = ['01', '10', '001', '101', '110', '011', '010', '111', '000', '1001', '0110', '1101'];

/** Deterministic particle field — stable across renders, no Math.random. */
const PARTICLES = Array.from({ length: 26 }, (_, i) => {
  const top = 6 + ((i * 31) % 88); // 6..94 %
  const depth = Math.abs(top - 50) / 50; // 0 center (far) → 1 edges (near)
  return {
    bits: PARTICLE_BITS[i % PARTICLE_BITS.length],
    top,
    left: 2 + ((i * 17) % 16), // 2..18 %
    size: 8 + Math.round(depth * 5), // 8px far → 13px near: perspective depth
    duration: 4.5 + ((i * 11) % 55) / 10, // 4.5..10s
    delay: -((i * 13) % 95) / 10, // negative: particles already in flight at mount
    violet: i % 6 === 3,
  };
});

/** Tunnel perspective rings: outer rings large/near, center ring small/far. */
const RINGS = [
  { cx: 148, ry: 86, rx: 15, opacity: 0.3, delay: 0 },
  { cx: 194, ry: 70, rx: 12, opacity: 0.38, delay: 0.55 },
  { cx: 240, ry: 56, rx: 10, opacity: 0.48, delay: 1.1 },
  { cx: 300, ry: 44, rx: 8, opacity: 0.62, delay: 1.65 },
  { cx: 360, ry: 56, rx: 10, opacity: 0.48, delay: 2.2 },
  { cx: 406, ry: 70, rx: 12, opacity: 0.38, delay: 2.75 },
  { cx: 452, ry: 86, rx: 15, opacity: 0.3, delay: 3.3 },
];

/** Inner tunnel layer — a second, deeper hull for parallax depth. */
const INNER_RINGS = [
  { cx: 258, ry: 34, rx: 6, opacity: 0.28, delay: 0.8 },
  { cx: 300, ry: 26, rx: 5, opacity: 0.34, delay: 2 },
  { cx: 342, ry: 34, rx: 6, opacity: 0.28, delay: 3.2 },
];

const TUBE_LEFT = 130;
const TUBE_RIGHT = 470;
const TUBE_MID_Y = 104;

/** Y positions of stream endpoints inside the 600x208 SVG, matching the node columns. */
const SOURCE_YS = [28, 66, 104, 142, 180];
const OUTPUT_YS = [44, 84, 124, 164];

function sourceStreamPath(y: number): string {
  return `M 0,${y} C ${TUBE_LEFT * 0.55},${y} ${TUBE_LEFT * 0.55},${TUBE_MID_Y} ${TUBE_LEFT},${TUBE_MID_Y}`;
}

function outputStreamPath(y: number): string {
  return `M ${TUBE_RIGHT},${TUBE_MID_Y} C ${600 - (600 - TUBE_RIGHT) * 0.55},${TUBE_MID_Y} ${
    600 - (600 - TUBE_RIGHT) * 0.55
  },${y} 600,${y}`;
}

export default function SecurityOperationsFlow({
  events,
  incidents,
  alerts,
}: {
  events: SecurityEvent[];
  incidents: Incident[];
  alerts: Alert[];
}) {
  const sourceCounts = useMemo(() => {
    const counts: Record<SourceKey, number> = { logs: 0, endpoints: 0, network: 0, identity: 0, cloud: 0 };
    for (const event of events) counts[classifySource(event.source)] += 1;
    return counts;
  }, [events]);

  const mlAnomalies = useMemo(
    () => alerts.filter((a) => a.detection_source === 'ml').length,
    [alerts],
  );

  const outputs = useMemo(
    () => [
      { label: 'INCIDENTS', count: incidents.length, to: '/incidents', icon: IconIncidents },
      { label: 'ALERTS', count: alerts.length, to: '/alerts', icon: IconAlerts },
      { label: 'ANOMALIES', count: mlAnomalies, to: '/analytics', icon: IconCpu },
      { label: 'REPORTS', count: null, to: '/reports', icon: IconReports },
    ],
    [incidents, alerts, mlAnomalies],
  );

  const pipeline = useMemo(() => {
    const investigating = incidents.some(
      (i) => i.status === 'investigating' || i.status === 'in_progress',
    );
    const responded = incidents.some((i) => i.status === 'resolved' || i.status === 'closed');
    return [
      { num: '01', name: 'COLLECT', sub: 'Telemetry ingestion', active: events.length > 0, icon: IconDatabase },
      { num: '02', name: 'DETECT', sub: 'Rules + ML anomaly', active: alerts.length > 0, icon: IconZap },
      { num: '03', name: 'CORRELATE', sub: 'Incident graph', active: incidents.length > 0, icon: IconNetwork },
      { num: '04', name: 'INVESTIGATE', sub: 'AI investigator', active: investigating, icon: IconInvestigator },
      { num: '05', name: 'RESPOND', sub: 'Contain & report', active: responded, icon: IconReports },
    ];
  }, [events, alerts, incidents]);

  const correlationActive = incidents.length > 0;
  const anyTelemetry = events.length > 0;

  return (
    <section className="flow-section panel" data-testid="operations-flow">
      <div className="panel-head">
        <h2 className="panel-title">Security Operations Flow</h2>
        <span className="panel-tag">LIVE PIPELINE</span>
      </div>

      <div className="flow-grid">
        <div className="flow-column">
          <div className="flow-column-label">Telemetry Sources</div>
          {SOURCES.map(({ key, label, icon: Icon }) => {
            const count = sourceCounts[key];
            return (
              <div key={key} className={`flow-node${count > 0 ? ' has-data' : ''}`}>
                <Icon size={14} />
                <span>{label}</span>
                <span className={`flow-led${count > 0 ? ' on' : ''}`} aria-hidden="true" />
                {count > 0 ? <span className="flow-count">{count}</span> : null}
              </div>
            );
          })}
        </div>

        <div className="flow-tube" role="img" aria-label="Animated data flow tunnel: telemetry streams into the Nexus One correlation engine and out to detections">
          <svg viewBox="0 0 600 208" preserveAspectRatio="none" aria-hidden="true">
            {/* Outer tunnel hull */}
            <path className="tube-hull" d={`M ${TUBE_LEFT},16 Q 300,110 ${TUBE_RIGHT},16`} />
            <path className="tube-hull" d={`M ${TUBE_LEFT},192 Q 300,98 ${TUBE_RIGHT},192`} />

            {/* Inner tunnel layer — depth */}
            <path className="tube-hull-inner" d={`M 196,46 Q 300,100 404,46`} />
            <path className="tube-hull-inner" d={`M 196,162 Q 300,108 404,162`} />

            {/* Perspective rings receding to the vanishing point */}
            {RINGS.map((ring) => (
              <ellipse
                key={`ring-${ring.cx}`}
                className="tube-ring"
                cx={ring.cx}
                cy={TUBE_MID_Y}
                rx={ring.rx}
                ry={ring.ry}
                style={{ opacity: ring.opacity, animationDelay: `${ring.delay}s` }}
              />
            ))}
            {INNER_RINGS.map((ring) => (
              <ellipse
                key={`inner-ring-${ring.cx}`}
                className="tube-ring tube-ring-inner"
                cx={ring.cx}
                cy={TUBE_MID_Y}
                rx={ring.rx}
                ry={ring.ry}
                style={{ opacity: ring.opacity, animationDelay: `${ring.delay}s` }}
              />
            ))}

            {/* Expanding engine pulse from the vanishing point */}
            <ellipse className="tube-pulse-ring" cx={300} cy={TUBE_MID_Y} rx={10} ry={44} />

            {/* Inbound streams: sources → engine */}
            {SOURCE_YS.map((y, i) => {
              const d = sourceStreamPath(y);
              return (
                <g key={`src-${y}`}>
                  <path className="tube-stream-glow" d={d} />
                  <path className="tube-stream" d={d} />
                  {anyTelemetry && i % 2 === 0 ? <path className="tube-stream-dash" d={d} /> : null}
                </g>
              );
            })}

            {/* Outbound streams: engine → outputs */}
            {OUTPUT_YS.map((y, i) => {
              const d = outputStreamPath(y);
              return (
                <g key={`out-${y}`}>
                  <path className="tube-stream-glow" d={d} />
                  <path className="tube-stream" d={d} />
                  {i === 2 ? (
                    <path className="tube-stream-dash-2" d={d} />
                  ) : (
                    <path className="tube-stream-dash" d={d} />
                  )}
                </g>
              );
            })}

            {/* Glowing junction nodes where streams meet the tunnel */}
            {SOURCE_YS.map((y, i) => (
              <circle
                key={`sj-${y}`}
                className="tube-junction"
                cx={12}
                cy={y}
                r={2.6}
                style={{ animationDelay: `${i * 0.45}s` }}
              />
            ))}
            <circle className="tube-junction-halo" cx={TUBE_LEFT} cy={TUBE_MID_Y} r={9} />
            <circle className="tube-junction-hub" cx={TUBE_LEFT} cy={TUBE_MID_Y} r={3.4} />
            <circle className="tube-junction-halo" cx={TUBE_RIGHT} cy={TUBE_MID_Y} r={9} style={{ animationDelay: '1.3s' }} />
            <circle className="tube-junction-hub" cx={TUBE_RIGHT} cy={TUBE_MID_Y} r={3.4} style={{ animationDelay: '0.65s' }} />
            {OUTPUT_YS.map((y, i) => (
              <circle
                key={`oj-${y}`}
                className="tube-junction"
                cx={588}
                cy={y}
                r={2.6}
                style={{ animationDelay: `${0.9 + i * 0.45}s` }}
              />
            ))}
          </svg>

          {/* Binary particles flowing through the tunnel */}
          <div className="tube-particles" aria-hidden="true">
            {PARTICLES.map((particle) => (
              <span
                key={particle.bits + particle.top}
                className={`tube-particle${particle.violet ? ' violet' : ''}`}
                style={{
                  top: `${particle.top}%`,
                  left: `${particle.left}%`,
                  fontSize: `${particle.size}px`,
                  animationDuration: `${particle.duration}s`,
                  animationDelay: `${particle.delay}s`,
                }}
              >
                {particle.bits}
              </span>
            ))}
          </div>

          <div className="tube-scan" aria-hidden="true" />

          <div className="tube-core">
            <div className="tube-core-engine" aria-hidden="true">
              <div className="engine-ring engine-ring-outer" />
              <div className="engine-ring engine-ring-inner" />
              <div className="engine-core-center">
                <span className="engine-zero-one">01</span>
              </div>
              <span className="engine-bit bit-1">1</span>
              <span className="engine-bit bit-2">0</span>
              <span className="engine-bit bit-3">1</span>
              <span className="engine-bit bit-4">0</span>
            </div>
            <span className="tube-core-label">Nexus One Engine</span>
            <span className="tube-core-sub">
              {events.length} EVENTS · {alerts.length} ALERTS
            </span>
            <span className={`tube-core-sub dim${correlationActive ? ' ok' : ''}`}>
              {correlationActive ? 'CORRELATION ACTIVE' : 'CORRELATION STANDBY'}
            </span>
          </div>
        </div>

        <div className="flow-column">
          <div className="flow-column-label">Detections</div>
          {outputs.map(({ label, count, to, icon: Icon }) => (
            <Link
              key={label}
              to={to}
              className={`flow-node output-node${count ? ' has-data' : ''}`}
            >
              <span className="flow-node-inner">
                <Icon size={14} />
                <span>{label}</span>
              </span>
              <span className="flow-count">{count ?? '—'}</span>
            </Link>
          ))}
        </div>
      </div>

      <div className="pipeline-row">
        {pipeline.map((step) => (
          <div key={step.num} className={`pipeline-step${step.active ? ' active-step' : ''}`}>
            <div className="pipeline-step-head">
              <span className="pipeline-step-icon">
                <step.icon size={13} />
              </span>
              <span className="pipeline-step-num">{step.num}</span>
              <span className={`pipeline-status${step.active ? ' on' : ''}`}>
                {step.active ? 'ACTIVE' : 'STANDBY'}
              </span>
            </div>
            <span className="pipeline-step-name">{step.name}</span>
            <span className="pipeline-step-sub">{step.sub}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
