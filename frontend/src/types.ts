// API types matching backend schemas

export type JobStatus = 'pending' | 'running' | 'completed' | 'failed';

export interface Finding {
  id: string;
  job_id: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description: string;
  evidence: string | null;
  remediation: string | null;
}

export interface AITriageFinding {
  priority_rank: number;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  business_risk: string;
  remediation: string;
  related_raw_ids: string[];
}

export interface AITriage {
  summary: string;
  findings: AITriageFinding[];
  _error?: string;
}

export interface ScanJob {
  id: string;
  target: string;
  status: JobStatus;
  requested_at: string;
  consent_confirmed: boolean;
  requester_ip: string | null;
  consent_at: string | null;
  error_message: string | null;
  findings: Finding[];
  ai_triage: AITriage | null;
}
