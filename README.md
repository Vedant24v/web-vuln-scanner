# Web Vulnerability Scanner

Authorized security testing only. Do not scan systems you do not own or have explicit written authorization to assess. Unauthorized scanning is illegal in most jurisdictions.

## What This Is

This project upgrades a Python web vulnerability scanner built on `requests`, `beautifulsoup4`, and `rich` into a deployable full-stack application:

- FastAPI backend with async background scan jobs
- React + TypeScript frontend with live polling and a redesigned dark operator-console UI
- PostgreSQL persistence for scan jobs, consent logs, and findings
- Groq-powered AI triage that deduplicates findings and re-ranks them by realistic exploitability
- HTML report download that reuses and extends the original report generator

The original detection logic for security headers, reflected XSS, SQL injection, and report generation is preserved and wrapped by the new service layer.

## Safety And Consent

The app is intentionally opinionated about abuse prevention.

- A scan cannot be submitted unless the user checks the mandatory authorization checkbox.
- The backend independently enforces that same consent requirement and stores the consent timestamp, target, and requester IP in the database.
- The scanner blocks localhost, private IP space, and `169.254.169.254` unless the target is explicitly whitelisted through `ALLOWED_PRIVATE_TARGETS` because it belongs to infrastructure you own.
- Rate limiting is enforced with one concurrent scan per session and five scan submissions per hour per IP.
- The landing page, API metadata, downloadable report, and this README all carry the legal-use warning.

## Feature Set

### Existing Scanner Checks

- Missing security headers
- Reflected XSS heuristics
- SQL injection heuristics
- HTML report generation

### Additional Passive Checks

- Insecure cookie flags: missing `Secure`, `HttpOnly`, or `SameSite`
- CORS misconfiguration: wildcard origin plus credentials, or reflected arbitrary origins
- Exposed sensitive files: `/.git/config`, `/.env`, `config.json`, backups, admin paths, Swagger paths
- Outdated JavaScript libraries: version parsing from script tags with a hardcoded stale-version list
- Directory listing exposure
- Basic API surface discovery: `swagger.json`, `openapi.json`, `/api/docs`, `/graphql`, actuator-style paths

## AI Triage Layer

Raw scanner output is noisy. The AI triage layer is the differentiator in this project.

After a scan completes, the backend sends the structured finding list to Groq with instructions to:

- deduplicate related findings
- re-rank by realistic exploitability instead of raw rule severity
- explain business impact in plain English
- generate concrete remediation guidance

Why it matters:

- It reduces alert fatigue.
- It helps developers focus on exploitable issues first.
- It makes findings readable by non-security stakeholders.

The UI shows AI-triaged findings first and keeps the raw scanner output in a collapsible section below.

## Architecture

### Backend

- `backend/main.py`: FastAPI app startup, CORS, `.env` loading
- `backend/routers/scans.py`: scan submission, polling, triage fetch, report download
- `backend/database.py`: SQLAlchemy async engine and session handling
- `backend/models.py`: `ScanJob` and `Finding`
- `backend/safety.py`: SSRF controls and rate limiting
- `backend/ai_triage.py`: Groq triage integration
- `scanner/engine.py`: background scan orchestration

### Frontend

- `frontend/src/pages/HomePage.tsx`: target submission flow and consent gate
- `frontend/src/pages/ResultsPage.tsx`: polling, AI triage cards, raw findings, report download
- `frontend/src/components/*`: consent, progress, severity badges, triage cards, raw findings

## Environment Variables

### Backend

- `DATABASE_URL`
  Local dev can use the SQLite fallback automatically.
  Production should use Neon Postgres.
- `GROQ_API_KEY`
- `ALLOWED_ORIGINS`
- `ALLOWED_PRIVATE_TARGETS`
  Comma-separated hostnames or IPs that represent infrastructure you own.

### Frontend

- `VITE_API_URL`

## Local Setup

### 1. Install backend dependencies

```bash
py -m venv .venv
.venv\Scripts\activate
py -m pip install -r backend/requirements.txt
```

### 2. Configure backend environment

Copy `.env.example` to `.env` and set:

```env
DATABASE_URL=postgresql+asyncpg://user:pass@host/db?sslmode=require
GROQ_API_KEY=gsk_your_key_here
ALLOWED_ORIGINS=http://localhost:5173
ALLOWED_PRIVATE_TARGETS=
```

### 3. Run the backend

```bash
py run.py
```

API health check:

```bash
curl http://localhost:8000/health
```

### 4. Run the frontend

```bash
cd frontend
copy .env.example .env.local
npm install
npm run dev
```

Frontend default URL:

```text
http://localhost:5173
```

## Deployment

### Neon

1. Create a free Neon project.
2. Copy the connection string.
3. Use it as `DATABASE_URL`.
4. If needed, convert `postgresql://` to `postgresql+asyncpg://` or `postgresql+psycopg://`.

### Render Backend

Use the included `Dockerfile` and `render.yaml`.

Required Render env vars:

```text
DATABASE_URL
GROQ_API_KEY
ALLOWED_ORIGINS
```

Expected free-tier behavior:

- Render free services cold start after inactivity.
- The first request after sleep can take about 30 to 50 seconds.

### Vercel Frontend

Deploy the `frontend/` directory as a Vite project.

Required Vercel env var:

```text
VITE_API_URL=https://your-render-service.onrender.com
```

## Verification Completed Locally

I validated the current build against a controlled local target owned for testing purposes.

- Consent-less submission was blocked.
- Session concurrency limiting returned `429`.
- The per-IP hourly limiter returned `429` on the sixth submission.
- The scanner completed successfully and persisted findings.
- HTML report generation worked and included the legal disclaimer.

Note on AI verification:

- Groq connectivity was confirmed.
- The current free-tier token limit can reject oversized triage requests if the payload is too verbose.
- The backend now compacts the AI payload to reduce that risk, but final production verification should be repeated after deployment with your real target mix.

## Files For Deployment

- [Dockerfile](/D:/Projects/web-vuln-scanner-main/Dockerfile)
- [render.yaml](/D:/Projects/web-vuln-scanner-main/render.yaml)
- [backend/requirements.txt](/D:/Projects/web-vuln-scanner-main/backend/requirements.txt)
- [frontend/.env.example](/D:/Projects/web-vuln-scanner-main/frontend/.env.example)

## Repo Layout

```text
backend/
frontend/
scanner/
run.py
Dockerfile
render.yaml
README.md
```
