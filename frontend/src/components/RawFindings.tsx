import { useState } from 'react';
import { ChevronDown, Database } from 'lucide-react';
import type { Finding } from '../types';
import { SeverityBadge } from './SeverityBadge';

interface RawFindingsProps {
  findings: Finding[];
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export function RawFindings({ findings }: RawFindingsProps) {
  const [open, setOpen] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const sorted = [...findings].sort(
    (left, right) => SEVERITY_ORDER.indexOf(left.severity) - SEVERITY_ORDER.indexOf(right.severity)
  );

  return (
    <section className="panel overflow-hidden">
      <button
        type="button"
        className="flex w-full items-center justify-between px-6 py-5 text-left"
        onClick={() => setOpen((current) => !current)}
      >
        <div className="flex items-center gap-3">
          <Database size={16} style={{ color: 'var(--accent)' }} />
          <div>
            <p className="section-title">Raw findings</p>
            <p className="mt-1 text-xs text-soft">Expanded evidence from the underlying scanner modules</p>
          </div>
        </div>

        <div className="chip">
          <span>{findings.length}</span>
          <ChevronDown
            size={14}
            style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s ease' }}
          />
        </div>
      </button>

      {open && (
        <div className="subtle-divider">
          {sorted.length === 0 ? (
            <div className="px-6 py-5 text-sm text-soft">No raw findings were stored for this scan.</div>
          ) : (
            sorted.map((finding) => (
              <div key={finding.id} className="subtle-divider first:border-t-0">
                <button
                  type="button"
                  className="flex w-full items-start gap-4 px-6 py-4 text-left"
                  onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
                >
                  <SeverityBadge severity={finding.severity} />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-semibold">{finding.category}</p>
                    <p className="mt-2 text-sm leading-6 text-soft">{finding.description}</p>
                  </div>
                  <ChevronDown
                    size={14}
                    className="mt-1 shrink-0 transition-transform"
                    style={{ transform: expandedId === finding.id ? 'rotate(180deg)' : 'rotate(0deg)' }}
                  />
                </button>

                {expandedId === finding.id && (
                  <div className="px-6 pb-5">
                    <div className="panel-muted space-y-4 p-4">
                      {finding.evidence && (
                        <div>
                          <p className="kicker">Evidence</p>
                          <code className="mt-3 block whitespace-pre-wrap break-all text-xs text-[var(--accent)]">
                            {finding.evidence}
                          </code>
                        </div>
                      )}

                      {finding.remediation && (
                        <div>
                          <p className="kicker">Recommended fix</p>
                          <p className="mt-3 text-sm leading-6 text-soft">{finding.remediation}</p>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}
    </section>
  );
}
