import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, Bot, ExternalLink, RefreshCw, ShieldCheck, TriangleAlert } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { getScan } from '../api';
import { DownloadReport } from '../components/DownloadReport';
import { RawFindings } from '../components/RawFindings';
import { ScanProgress } from '../components/ScanProgress';
import { SeverityBadge } from '../components/SeverityBadge';
import { TriageCard } from '../components/TriageCard';
import type { ScanJob } from '../types';

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function SeveritySummary({ findings }: { findings: ScanJob['findings'] }) {
  const counts = findings.reduce<Record<string, number>>((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="chip-row">
      {SEVERITY_ORDER.filter((severity) => counts[severity]).map((severity) => (
        <div key={severity} className="chip">
          <SeverityBadge severity={severity} size="md" />
          <strong>{counts[severity]}</strong>
        </div>
      ))}
    </div>
  );
}

export function ResultsPage() {
  const { id } = useParams<{ id: string }>();
  const [job, setJob] = useState<ScanJob | null>(null);
  const [error, setError] = useState('');
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchJob = async () => {
    if (!id) {
      return;
    }

    try {
      const data = await getScan(id);
      setJob(data);
      if (data.status === 'completed' || data.status === 'failed') {
        if (intervalRef.current) {
          clearInterval(intervalRef.current);
        }
      }
    } catch {
      setError('Could not load scan results. Check that the backend is running.');
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    }
  };

  useEffect(() => {
    fetchJob();
    intervalRef.current = setInterval(fetchJob, 3000);
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [id]);

  const isActive = job?.status === 'pending' || job?.status === 'running';

  return (
    <main className="app-shell">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <Link to="/" className="btn btn-secondary w-fit">
          <ArrowLeft size={16} />
          New scan
        </Link>
        {job?.status === 'completed' && <DownloadReport jobId={job.id} />}
      </div>

      {error && (
        <section className="legal-banner mt-5" style={{ borderColor: 'rgba(255,124,118,0.24)', background: 'rgba(255,124,118,0.08)', color: '#ffc3bf' }}>
          <div className="flex items-start gap-3">
            <TriangleAlert size={18} className="mt-0.5 shrink-0" />
            <p className="text-sm leading-6">{error}</p>
          </div>
        </section>
      )}

      {!job && !error && (
        <section className="panel mt-5 p-8 text-center fade-in-up">
          <RefreshCw size={20} className="mx-auto animate-spin" style={{ color: 'var(--accent)' }} />
          <p className="mt-4 text-sm text-soft">Loading scan details...</p>
        </section>
      )}

      {job && (
        <div className="mt-5 space-y-5 fade-in-up">
          <section className="panel p-6 md:p-8">
            <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
              <div className="min-w-0 flex-1">
                <p className="kicker">Target</p>
                <h1 className="mt-3 break-all text-2xl font-bold">{job.target}</h1>
                <div className="mt-4 info-grid">
                  <div className="panel-muted p-4">
                    <p className="kicker">Status</p>
                    <div className="mt-3 flex items-center gap-2">
                      <ShieldCheck size={16} style={{ color: 'var(--accent)' }} />
                      <span className="text-sm capitalize text-soft">{job.status}</span>
                    </div>
                  </div>
                  <div className="panel-muted p-4">
                    <p className="kicker">Requested</p>
                    <p className="mt-3 text-sm text-soft">{new Date(job.requested_at).toLocaleString()}</p>
                  </div>
                  <div className="panel-muted p-4">
                    <p className="kicker">Consent logged</p>
                    <p className="mt-3 text-sm text-soft">
                      {job.consent_at ? new Date(job.consent_at).toLocaleString() : 'Pending'}
                    </p>
                  </div>
                </div>
              </div>

              <div className="panel-muted p-4 min-w-[260px]">
                <p className="kicker">Scan record</p>
                <p className="mt-3 text-sm leading-6 text-soft">
                  Job <span className="font-mono">{job.id.slice(0, 8)}</span> is stored with the
                  consent flag and requester IP for auditability.
                </p>
                {job.status === 'completed' && job.findings.length > 0 && (
                  <div className="mt-4">
                    <SeveritySummary findings={job.findings} />
                  </div>
                )}
              </div>
            </div>
          </section>

          {isActive && (
            <ScanProgress status={job.status} target={job.target} findingCount={job.findings.length} />
          )}

          {job.status === 'failed' && (
            <section className="panel p-6">
              <div className="section-title">
                <TriangleAlert size={16} style={{ color: 'var(--danger)' }} />
                Scan failed
              </div>
              <p className="mt-4 text-sm leading-6 text-soft">
                {job.error_message || 'An unexpected error occurred during the scan.'}
              </p>
            </section>
          )}

          {job.status === 'completed' && (
            <section className="panel p-6 md:p-8">
              <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
                <div>
                  <div className="section-title">
                    <Bot size={16} style={{ color: 'var(--accent)' }} />
                    AI-triaged findings
                  </div>
                  <p className="mt-2 text-sm leading-6 text-soft">
                    The Groq layer deduplicates overlapping issues and re-orders them by realistic
                    exploitability before you review the raw evidence.
                  </p>
                </div>
                <div className="chip">
                  <ExternalLink size={14} />
                  llama-3.1 triage
                </div>
              </div>

              {job.ai_triage?.summary && (
                <div className="panel-muted mt-6 p-5">
                  <p className="kicker">Executive summary</p>
                  <p className="mt-3 text-sm leading-7 text-soft">{job.ai_triage.summary}</p>
                </div>
              )}

              {job.ai_triage?.findings?.length ? (
                <div className="stagger mt-6 space-y-3">
                  {job.ai_triage.findings.map((finding, index) => (
                    <TriageCard key={`${finding.category}-${index}`} finding={finding} index={index} />
                  ))}
                </div>
              ) : (
                <div className="panel-muted mt-6 p-5">
                  <p className="text-sm text-soft">
                    {job.ai_triage
                      ? 'AI triage returned no additional priority findings.'
                      : 'AI triage unavailable. Raw findings are still listed below.'}
                  </p>
                </div>
              )}
            </section>
          )}

          {job.status === 'completed' && <RawFindings findings={job.findings} />}
        </div>
      )}
    </main>
  );
}
