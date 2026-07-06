import { useState } from 'react';
import { ChevronDown, ShieldAlert, Wrench } from 'lucide-react';
import type { AITriageFinding } from '../types';
import { SeverityBadge } from './SeverityBadge';

interface TriageCardProps {
  finding: AITriageFinding;
  index: number;
}

export function TriageCard({ finding, index }: TriageCardProps) {
  const [expanded, setExpanded] = useState(index < 2);

  return (
    <article className="triage-card" data-severity={finding.severity}>
      <button
        type="button"
        className="flex w-full items-center gap-4 p-5 text-left"
        onClick={() => setExpanded((current) => !current)}
      >
        <div className="panel-muted flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl text-sm font-bold">
          #{finding.priority_rank}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <h3 className="text-base font-semibold">{finding.category}</h3>
          </div>
          <p className="mt-2 text-sm leading-6 text-soft">
            {finding.business_risk}
          </p>
        </div>

        <ChevronDown
          size={18}
          className="shrink-0 transition-transform"
          style={{ transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)', color: 'var(--text-dim)' }}
        />
      </button>

      {expanded && (
        <div className="subtle-divider px-5 pb-5">
          <div className="mt-4 space-y-4">
            <div className="flex gap-3">
              <ShieldAlert size={16} className="mt-1 shrink-0" style={{ color: 'var(--accent)' }} />
              <div>
                <p className="kicker">Business risk</p>
                <p className="mt-2 text-sm leading-6 text-soft">{finding.business_risk}</p>
              </div>
            </div>
            <div className="flex gap-3">
              <Wrench size={16} className="mt-1 shrink-0" style={{ color: 'var(--accent-2)' }} />
              <div>
                <p className="kicker">Remediation</p>
                <p className="mt-2 text-sm leading-6 text-soft">{finding.remediation}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </article>
  );
}
