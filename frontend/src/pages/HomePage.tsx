import { FormEvent, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Bot,
  FileWarning,
  Radar,
  Shield,
  Target,
  Waypoints,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { submitScan } from '../api';
import { ConsentForm } from '../components/ConsentForm';

const MODULES = [
  'Security headers and cookie controls',
  'Reflected XSS and SQLi heuristics',
  'CORS, API docs, and directory listing exposure',
  'Exposed files, backup artifacts, and stale JS libraries',
];

const HIGHLIGHTS = [
  { icon: Shield, label: 'Guardrails first', value: 'Consent gate + SSRF denylist' },
  { icon: Radar, label: 'Scan model', value: 'Passive and low-impact checks' },
  { icon: Bot, label: 'AI triage', value: 'Groq-backed exploitability ranking' },
  { icon: FileWarning, label: 'Reporting', value: 'Downloadable HTML artifact' },
];

export function HomePage() {
  const navigate = useNavigate();
  const [target, setTarget] = useState('');
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError('');

    if (!consent) {
      setError('You must confirm ownership or written authorization before starting a scan.');
      return;
    }

    if (!target.startsWith('http://') && !target.startsWith('https://')) {
      setError('Target must start with http:// or https://');
      return;
    }

    setLoading(true);
    try {
      const job = await submitScan(target, consent);
      navigate(`/scan/${job.id}`);
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string };
      setError(axiosErr?.response?.data?.detail || axiosErr?.message || 'Failed to submit scan.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="app-shell">
      <section className="legal-banner mb-5 fade-in-up">
        <div className="flex items-start gap-3">
          <AlertTriangle size={18} className="mt-0.5 shrink-0" />
          <p className="text-sm leading-6">
            This tool is for authorized security testing only. Do not scan systems you do not own
            or have explicit written authorization to assess.
          </p>
        </div>
      </section>

      <section className="hero-grid mb-6">
        <div className="panel p-7 md:p-9 fade-in-up">
          <span className="eyebrow">
            <Target size={14} />
            Authorized Web Security Testing
          </span>
          <p className="kicker mt-6">FastAPI backend • React dashboard • AI triage layer</p>
          <h1 className="display-title">
            Scanner output you can
            <br />
            actually act on.
          </h1>
          <p className="text-soft max-w-2xl text-[1.02rem] leading-7">
            Run a black-box scan, enforce consent before execution, keep scans rate-limited, and
            surface the results as an exploitability-ranked triage feed instead of a noisy wall of
            raw findings.
          </p>

          <div className="info-grid mt-7">
            {HIGHLIGHTS.map(({ icon: Icon, label, value }) => (
              <div key={label} className="metric-tile">
                <Icon size={18} style={{ color: 'var(--accent)' }} />
                <span className="kicker mt-4 block">{label}</span>
                <strong>{value}</strong>
              </div>
            ))}
          </div>
        </div>

        <aside className="panel p-6 md:p-7 fade-in-up" style={{ animationDelay: '0.06s' }}>
          <div className="section-title">
            <Waypoints size={16} style={{ color: 'var(--accent)' }} />
            Coverage Snapshot
          </div>
          <div className="subtle-divider my-5" />
          <div className="space-y-4">
            {MODULES.map((module, index) => (
              <div key={module} className="panel-muted p-4">
                <p className="kicker">Module {index + 1}</p>
                <p className="mt-2 text-sm leading-6 text-soft">{module}</p>
              </div>
            ))}
          </div>
          <div className="panel-muted mt-5 p-4">
            <p className="kicker">Rate limits</p>
            <p className="mt-2 text-sm leading-6 text-soft">
              One concurrent scan per session, five submissions per hour per IP, and metadata or
              private targets blocked unless explicitly whitelisted as infrastructure you own.
            </p>
          </div>
        </aside>
      </section>

      <section className="panel p-6 md:p-8 fade-in-up" style={{ animationDelay: '0.12s' }}>
        <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <p className="kicker">Start a scan</p>
            <h2 className="mt-2 text-2xl font-bold">Submit a target for background analysis</h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-soft">
              The scanner runs asynchronously, logs your consent to the database, and lets you poll
              status until AI triage and the HTML report are ready.
            </p>
          </div>
          <div className="chip-row">
            <span className="chip">
              <span className="status-dot" style={{ background: 'var(--accent)' }} />
              Groq triage
            </span>
            <span className="chip">
              <span className="status-dot" style={{ background: 'var(--accent-2)' }} />
              HTML report
            </span>
          </div>
        </div>

        <form className="mt-7 space-y-5" onSubmit={handleSubmit}>
          <div>
            <label className="kicker block mb-3" htmlFor="target-input">
              Target URL
            </label>
            <input
              id="target-input"
              type="url"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              className="scan-input font-mono text-sm"
              placeholder="https://example.com/search?q=test"
              required
            />
          </div>

          <ConsentForm checked={consent} onChange={setConsent} />

          {error && (
            <div className="legal-banner" style={{ borderColor: 'rgba(255,124,118,0.25)', background: 'rgba(255,124,118,0.08)', color: '#ffc3bf' }}>
              <div className="flex items-start gap-3">
                <AlertTriangle size={16} className="mt-0.5 shrink-0" />
                <p className="text-sm leading-6">{error}</p>
              </div>
            </div>
          )}

          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <p className="text-sm leading-6 text-soft">
              Low-impact checks only. Findings still require validation in context before remediation.
            </p>
            <button id="submit-scan-btn" type="submit" disabled={loading || !consent} className="btn btn-primary min-w-[220px]">
              {loading ? 'Submitting...' : 'Launch Background Scan'}
              {!loading && <ArrowRight size={16} />}
            </button>
          </div>
        </form>
      </section>
    </main>
  );
}
