"""
Scan API router.
POST /api/scans             - submit a scan (with consent check + rate limit)
GET  /api/scans/{id}        - poll status + findings
GET  /api/scans/{id}/report - download HTML report
GET  /api/scans/{id}/triage - get AI triage result
"""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.database import AsyncSessionLocal, get_db
from backend.models import JobStatus, ScanJob
from backend.safety import check_rate_limit, is_ssrf_blocked
from backend.schemas import FindingOut, ScanJobOut, ScanRequest
from scanner.engine import generate_html_report_for_job, run_full_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _get_session_id(request: Request) -> str:
    header_session = request.headers.get("X-Scan-Session", "").strip()
    cookie_session = request.cookies.get("scan_session", "").strip()
    return header_session or cookie_session or _get_client_ip(request)


@router.post("", response_model=ScanJobOut, status_code=202)
async def create_scan(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Submit a new scan job."""
    if not body.consent_confirmed:
        raise HTTPException(
            status_code=400,
            detail="Consent is required. You must confirm ownership or written authorization.",
        )

    blocked, reason = is_ssrf_blocked(body.target)
    if blocked:
        raise HTTPException(status_code=403, detail=f"Target blocked: {reason}")

    client_ip = _get_client_ip(request)
    session_id = _get_session_id(request)
    allowed, rl_reason = check_rate_limit(client_ip, session_id)
    if not allowed:
        raise HTTPException(status_code=429, detail=rl_reason)

    job = ScanJob(
        target=body.target,
        status=JobStatus.pending,
        consent_confirmed=True,
        requester_ip=client_ip,
        consent_at=datetime.now(timezone.utc),
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    background_tasks.add_task(
        run_full_scan,
        job_id=job.id,
        target=body.target,
        requester_ip=client_ip,
        session_id=session_id,
        db_session_factory=AsyncSessionLocal,
    )

    return ScanJobOut(
        id=job.id,
        target=job.target,
        status=job.status,
        requested_at=job.requested_at,
        consent_confirmed=job.consent_confirmed,
        requester_ip=job.requester_ip,
        consent_at=job.consent_at,
    )


@router.get("/{job_id}", response_model=ScanJobOut)
async def get_scan(job_id: str, db: AsyncSession = Depends(get_db)):
    """Poll scan status and retrieve findings."""
    result = await db.execute(
        select(ScanJob).options(selectinload(ScanJob.findings)).where(ScanJob.id == job_id)
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found.")

    ai_triage = None
    if job.ai_triage_json:
        try:
            ai_triage = json.loads(job.ai_triage_json)
        except Exception:
            ai_triage = None

    return ScanJobOut(
        id=job.id,
        target=job.target,
        status=job.status,
        requested_at=job.requested_at,
        consent_confirmed=job.consent_confirmed,
        requester_ip=job.requester_ip,
        consent_at=job.consent_at,
        error_message=job.error_message,
        findings=[
            FindingOut(
                id=finding.id,
                job_id=finding.job_id,
                category=finding.category,
                severity=finding.severity,
                description=finding.description,
                evidence=finding.evidence,
                remediation=finding.remediation,
            )
            for finding in job.findings
        ],
        ai_triage=ai_triage,
    )


@router.get("/{job_id}/report")
async def download_report(job_id: str, db: AsyncSession = Depends(get_db)):
    """Generate and download the HTML report using the existing report generator."""
    result = await db.execute(
        select(ScanJob).options(selectinload(ScanJob.findings)).where(ScanJob.id == job_id)
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    if job.status != JobStatus.completed:
        raise HTTPException(status_code=400, detail="Scan not yet complete.")

    html_path = generate_html_report_for_job(job.target, job.findings)
    return FileResponse(
        path=html_path,
        media_type="text/html",
        filename=f"vuln-report-{job_id[:8]}.html",
    )


@router.get("/{job_id}/triage")
async def get_triage(job_id: str, db: AsyncSession = Depends(get_db)):
    """Return the AI triage JSON for a completed scan."""
    result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    if job.status != JobStatus.completed:
        raise HTTPException(status_code=400, detail="Scan not yet complete.")

    if not job.ai_triage_json:
        return JSONResponse({"summary": "AI triage not available.", "findings": []})

    try:
        return JSONResponse(json.loads(job.ai_triage_json))
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to parse AI triage data.") from exc
