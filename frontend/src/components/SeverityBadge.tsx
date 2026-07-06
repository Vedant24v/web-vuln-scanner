type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

interface SeverityBadgeProps {
  severity: Severity | string;
  size?: 'sm' | 'md';
}

const CONFIG: Record<string, { label: string; color: string; bg: string; dot: string }> = {
  CRITICAL: { label: 'CRITICAL', color: '#ff7c76', bg: 'rgba(255,124,118,0.14)', dot: '#ff7c76' },
  HIGH:     { label: 'HIGH', color: '#ffb454', bg: 'rgba(255,180,84,0.15)', dot: '#ffb454' },
  MEDIUM:   { label: 'MEDIUM', color: '#ffe07a', bg: 'rgba(255,224,122,0.14)', dot: '#ffe07a' },
  LOW:      { label: 'LOW', color: '#5dd6ff', bg: 'rgba(93,214,255,0.12)', dot: '#5dd6ff' },
  INFO:     { label: 'INFO', color: '#8db2ff', bg: 'rgba(141,178,255,0.14)', dot: '#8db2ff' },
};

export function SeverityBadge({ severity, size = 'sm' }: SeverityBadgeProps) {
  const cfg = CONFIG[severity?.toUpperCase?.()] || CONFIG.INFO;
  const isLarge = size === 'md';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-bold tracking-[0.16em] uppercase ${isLarge ? 'px-3 py-1.5 text-[11px]' : 'px-2.5 py-1 text-[10px]'}`}
      style={{ color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.color}33` }}
    >
      <span
        className="rounded-full flex-shrink-0"
        style={{ width: 5, height: 5, background: cfg.dot }}
      />
      {cfg.label}
    </span>
  );
}
