import { CheckCircle2, Clock3, Loader2, XCircle } from 'lucide-react';
import type { JobStatus } from '../types';

interface ScanProgressProps {
  status: JobStatus;
  target: string;
  findingCount: number;
}

const STEPS = [
  'Fetch root response',
  'Check headers and cookie controls',
  'Probe XSS and SQLi patterns',
  'Review CORS and public files',
  'Inspect API and directory exposure',
  'Run AI triage and persist results',
];

export function ScanProgress({ status, target, findingCount }: ScanProgressProps) {
  const isRunning = status === 'pending' || status === 'running';

  return (
    <section className="panel p-6 md:p-7">
      <div className="flex items-start gap-4">
        <div className="panel-muted flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl">
          {isRunning ? (
            <Loader2 size={18} className="animate-spin" style={{ color: 'var(--accent)' }} />
          ) : status === 'completed' ? (
            <CheckCircle2 size={18} style={{ color: 'var(--success)' }} />
          ) : status === 'failed' ? (
            <XCircle size={18} style={{ color: 'var(--danger)' }} />
          ) : (
            <Clock3 size={18} style={{ color: 'var(--text-dim)' }} />
          )}
        </div>

        <div className="min-w-0 flex-1">
          <div className="section-title">
            {status === 'pending' && 'Queued and waiting for worker execution'}
            {status === 'running' && 'Scanner is running in the background'}
            {status === 'completed' && `Scan complete with ${findingCount} finding${findingCount === 1 ? '' : 's'}`}
            {status === 'failed' && 'Scan failed before completion'}
          </div>
          <p className="mt-2 break-all font-mono text-xs text-soft">{target}</p>
        </div>
      </div>

      {isRunning && (
        <>
          <div className="mt-6 h-2 overflow-hidden rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
            <div
              className="h-full rounded-full"
              style={{
                width: status === 'pending' ? '14%' : '68%',
                background: 'linear-gradient(90deg, var(--accent), var(--accent-2))',
                transition: 'width 0.9s ease',
              }}
            />
          </div>
          <p className="mt-3 text-sm text-soft">
            Background job execution is active. Polling will continue until triage and report generation finish.
          </p>
        </>
      )}

      <div className="mt-6 grid gap-3 md:grid-cols-2">
        {STEPS.map((step, index) => {
          const activeIndex = status === 'pending' ? 0 : 3;
          const isDone = status === 'completed';
          const isHighlighted = isRunning && index <= activeIndex;
          return (
            <div key={step} className="panel-muted flex items-center gap-3 p-3">
              <span
                className="status-dot"
                style={{
                  background: isDone ? 'var(--success)' : isHighlighted ? 'var(--accent)' : 'rgba(255,255,255,0.14)',
                  boxShadow: isHighlighted ? '0 0 0 4px rgba(93,214,255,0.12)' : 'none',
                }}
              />
              <span className="text-sm text-soft">{step}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}
