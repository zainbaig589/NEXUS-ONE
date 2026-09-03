/**
 * Inline SVG icon set — stroke-based, inherits currentColor.
 * Zero icon-library dependency keeps the bundle light.
 */

type IconProps = { size?: number; className?: string };

function Svg({
  size = 18,
  className,
  children,
  viewBox = '0 0 24 24',
}: IconProps & { children: React.ReactNode; viewBox?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox={viewBox}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

export function IconShield({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-4z" />
    </Svg>
  );
}

export function IconDashboard({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <rect x="3" y="3" width="7" height="9" rx="1.5" />
      <rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" />
      <rect x="3" y="16" width="7" height="5" rx="1.5" />
    </Svg>
  );
}

export function IconIncidents({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" />
      <path d="M12 9v4M12 17h.01" />
    </Svg>
  );
}

export function IconAlerts({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.7 21a2 2 0 01-3.4 0" />
    </Svg>
  );
}

export function IconThreatIntel({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3a15 15 0 014 9 15 15 0 01-4 9 15 15 0 01-4-9 15 15 0 014-9z" />
    </Svg>
  );
}

export function IconInvestigator({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <path d="M12 3a4 4 0 00-4 4c0 1.1.45 2.1 1.17 2.83L8 11a5.66 5.66 0 00-2 4c0 2 1 3 1 3" />
      <path d="M12 3a4 4 0 014 4c0 1.1-.45 2.1-1.17 2.83L16 11a5.66 5.66 0 012 4c0 2-1 3-1 3" />
      <path d="M10 21h4" />
      <circle cx="12" cy="7" r="1" />
    </Svg>
  );
}

export function IconReports({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
      <path d="M14 2v6h6M9 13h6M9 17h4" />
    </Svg>
  );
}

export function IconAssets({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <rect x="2" y="3" width="20" height="5" rx="1.5" />
      <rect x="2" y="10" width="20" height="5" rx="1.5" />
      <rect x="2" y="17" width="20" height="5" rx="1.5" />
      <path d="M6 5.5h.01M6 12.5h.01M6 19.5h.01" />
    </Svg>
  );
}

export function IconAnalytics({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <path d="M3 3v18h18" />
      <path d="M7 15l4-5 3 3 5-7" />
    </Svg>
  );
}

export function IconSettings({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <path d="M4 6h10M18 6h2M4 12h2M10 12h10M4 18h10M18 18h2" />
      <circle cx="16" cy="6" r="2" />
      <circle cx="8" cy="12" r="2" />
      <circle cx="16" cy="18" r="2" />
    </Svg>
  );
}

export function IconSearch({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <circle cx="11" cy="11" r="7" />
      <path d="M21 21l-4.35-4.35" />
    </Svg>
  );
}

export function IconRefresh({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <path d="M21 12a9 9 0 11-2.64-6.36" />
      <path d="M21 3v6h-6" />
    </Svg>
  );
}

export function IconActivity({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
    </Svg>
  );
}

export function IconDatabase({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <ellipse cx="12" cy="5" rx="8" ry="3" />
      <path d="M4 5v6c0 1.66 3.58 3 8 3s8-1.34 8-3V5" />
      <path d="M4 11v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6" />
    </Svg>
  );
}

export function IconCpu({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <rect x="6" y="6" width="12" height="12" rx="2" />
      <rect x="10" y="10" width="4" height="4" rx="1" />
      <path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2" />
    </Svg>
  );
}

export function IconGlobe({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3a15 15 0 014 9 15 15 0 01-4 9 15 15 0 01-4-9 15 15 0 014-9z" />
    </Svg>
  );
}

export function IconLogs({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <path d="M4 4h16v16H4z" />
      <path d="M8 9h8M8 13h8M8 17h5" />
    </Svg>
  );
}

export function IconEndpoint({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <rect x="2" y="4" width="20" height="13" rx="2" />
      <path d="M8 21h8M12 17v4" />
    </Svg>
  );
}

export function IconNetwork({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <circle cx="12" cy="5" r="2.5" />
      <circle cx="5" cy="19" r="2.5" />
      <circle cx="19" cy="19" r="2.5" />
      <path d="M12 7.5v4M12 11.5L6.5 17M12 11.5l5.5 5.5" />
    </Svg>
  );
}

export function IconIdentity({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <circle cx="12" cy="8" r="4" />
      <path d="M5 21a7 7 0 0114 0" />
    </Svg>
  );
}

export function IconCloud({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <path d="M17.5 19a4.5 4.5 0 100-9 6 6 0 10-11.74 2.13A3.5 3.5 0 006.5 19h11z" />
    </Svg>
  );
}

export function IconArrowRight({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <path d="M5 12h14M13 6l6 6-6 6" />
    </Svg>
  );
}

export function IconZap({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <path d="M13 2L3 14h7l-1 8 10-12h-7l1-8z" />
    </Svg>
  );
}

export function IconBell({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className} viewBox="0 0 24 24">
      <path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.7 21a2 2 0 01-3.4 0" />
    </Svg>
  );
}

export function IconMapPin({ size, className }: IconProps) {
  return (
    <Svg size={size} className={className}>
      <path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0116 0z" />
      <circle cx="12" cy="10" r="3" />
    </Svg>
  );
}
