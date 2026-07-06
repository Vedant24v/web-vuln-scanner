"""
Scan engine orchestrator.
Runs all detection modules and persists findings to the database.
"""

import asyncio
import json
import logging
import tempfile
from typing import Any

import requests as req_lib
from sqlalchemy import select

from backend.ai_triage import run_ai_triage
from backend.models import Finding, JobStatus, ScanJob
from backend.safety import release_rate_limit_slot
from scanner.api_surface import check_api_surface
from scanner.cookies import check_cookies
from scanner.cors import check_cors
from scanner.directory_listing import check_directory_listing
from scanner.exposed_files import check_exposed_files
from scanner.headers import check_headers
from scanner.js_libs import check_js_libraries
from scanner.reporter import generate_report
from scanner.sqli import check_sqli
from scanner.xss import check_xss

logger = logging.getLogger(__name__)


def _finding_to_db(job_id: str, raw: dict[str, Any]) -> Finding:
    """Convert a raw finding dict to a Finding ORM object."""
    return Finding(
        job_id=job_id,
        category=raw.get("type", "Unknown"),
        severity=raw.get("severity", "INFO"),
        description=raw.get("detail", ""),
        evidence=raw.get("evidence") or raw.get("url", ""),
        remediation=raw.get("remediation", ""),
    )


async def run_full_scan(
    job_id: str,
    target: str,
    requester_ip: str,
    session_id: str,
    db_session_factory,
):
    """
    Main async scan orchestrator.
    Runs in a FastAPI BackgroundTask and does not block the API.
    """
    logger.info("[%s] Starting scan of %s", job_id, target)

    async with db_session_factory() as db:
        result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
        job = result.scalar_one_or_none()
        if not job:
            logger.error("[%s] Job not found in DB", job_id)
            return

        job.status = JobStatus.running
        await db.commit()

    all_raw_findings: list[dict[str, Any]] = []

    try:
        def _fetch():
            try:
                response = req_lib.get(target, timeout=15, allow_redirects=True)
                return response, None
            except req_lib.RequestException as exc:
                return None, str(exc)

        loop = asyncio.get_running_loop()
        response, fetch_error = await loop.run_in_executor(None, _fetch)

        if fetch_error or response is None:
            raise RuntimeError(f"Could not reach target: {fetch_error}")

        def _run_sync_modules():
            results: list[dict[str, Any]] = []
            header_findings, _ = check_headers(response)
            results.extend(header_findings)
            results.extend(check_xss(target))
            results.extend(check_sqli(target))
            results.extend(check_cookies(response))
            results.extend(check_cors(response))
            results.extend(check_js_libraries(response))
            return results

        def _run_network_modules():
            results: list[dict[str, Any]] = []
            results.extend(check_exposed_files(target))
            results.extend(check_directory_listing(target))
            results.extend(check_api_surface(target))
            return results

        sync_task = loop.run_in_executor(None, _run_sync_modules)
        network_task = loop.run_in_executor(None, _run_network_modules)

        sync_results, network_results = await asyncio.gather(sync_task, network_task)
        all_raw_findings.extend(sync_results)
        all_raw_findings.extend(network_results)

        async with db_session_factory() as db:
            result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
            job = result.scalar_one_or_none()
            if not job:
                raise RuntimeError("Scan job disappeared before findings could be stored.")

            for raw in all_raw_findings:
                db.add(_finding_to_db(job_id, raw))

            findings_for_triage = [
                {
                    "id": f"raw_{index}",
                    "category": finding.get("type", "Unknown"),
                    "severity": finding.get("severity", "INFO"),
                    "description": finding.get("detail", ""),
                    "evidence": finding.get("evidence") or finding.get("url", ""),
                }
                for index, finding in enumerate(all_raw_findings)
            ]

            triage_result = await run_ai_triage(findings_for_triage)
            job.ai_triage_json = json.dumps(triage_result) if triage_result else None
            job.status = JobStatus.completed
            await db.commit()

        logger.info("[%s] Scan complete - %s findings", job_id, len(all_raw_findings))

    except Exception as exc:
        logger.exception("[%s] Scan failed: %s", job_id, exc)
        async with db_session_factory() as db:
            result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
            job = result.scalar_one_or_none()
            if job:
                job.status = JobStatus.failed
                job.error_message = str(exc)
                await db.commit()
    finally:
        release_rate_limit_slot(requester_ip, session_id)


def generate_html_report_for_job(target: str, findings: list) -> str:
    """Convert DB Finding objects to raw dicts and call the existing reporter."""
    raw_findings = [
        {
            "type": finding.category,
            "severity": finding.severity,
            "detail": finding.description,
            "evidence": finding.evidence or "",
            "remediation": finding.remediation or "",
        }
        for finding in findings
    ]

    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
        tmp_path = tmp.name

    generate_report(target, raw_findings, output_file=tmp_path)
    return tmp_path
