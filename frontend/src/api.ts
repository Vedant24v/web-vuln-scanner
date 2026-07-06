import axios from 'axios';
import type { ScanJob } from './types';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const SESSION_STORAGE_KEY = 'web_vuln_scan_session';

function getSessionId(): string {
  const existing = window.localStorage.getItem(SESSION_STORAGE_KEY);
  if (existing) {
    return existing;
  }

  const created =
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID()
      : `scan-${Date.now()}-${Math.random().toString(16).slice(2)}`;

  window.localStorage.setItem(SESSION_STORAGE_KEY, created);
  return created;
}

const api = axios.create({ baseURL: API_BASE });

api.interceptors.request.use((config) => {
  config.headers = config.headers ?? {};
  config.headers['X-Scan-Session'] = getSessionId();
  return config;
});

export async function submitScan(target: string, consentConfirmed: boolean): Promise<ScanJob> {
  const { data } = await api.post('/api/scans', {
    target,
    consent_confirmed: consentConfirmed,
  });
  return data;
}

export async function getScan(jobId: string): Promise<ScanJob> {
  const { data } = await api.get(`/api/scans/${jobId}`);
  return data;
}

export function getReportUrl(jobId: string): string {
  return `${API_BASE}/api/scans/${jobId}/report`;
}
