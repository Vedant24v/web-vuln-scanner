"""
AI triage layer using Groq's llama-3.1 model family.
"""

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

MODEL = "llama-3.1-8b-instant"

SYSTEM_PROMPT = """
You are triaging automated web security findings.
Deduplicate related items, rank by realistic exploitability, explain business risk in plain English,
and give specific remediation. Return JSON only:
{"summary":"...","findings":[{"priority_rank":1,"category":"...","severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO","business_risk":"...","remediation":"...","related_raw_ids":["raw_1"]}]}
"""


def _get_api_key() -> str:
    return os.environ.get("GROQ_API_KEY", "").strip()


def _compact_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compacted = []
    for finding in findings:
        compacted.append(
            {
                "i": finding.get("id"),
                "c": finding.get("category", "Unknown"),
                "s": finding.get("severity", "INFO"),
                "d": str(finding.get("description", ""))[:120],
            }
        )
    return compacted


async def run_ai_triage(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    """
    Send findings to Groq and return structured triage JSON.
    Returns None if Groq is not configured.
    """
    api_key = _get_api_key()
    if not api_key:
        logger.warning("GROQ_API_KEY not set - skipping AI triage.")
        return None

    if not findings:
        return {
            "summary": "No vulnerabilities were detected during this scan.",
            "findings": [],
        }

    try:
        from groq import AsyncGroq

        client = AsyncGroq(api_key=api_key)
        compact_findings = _compact_findings(findings)
        user_message = (
            "Findings JSON:\n"
            f"{json.dumps(compact_findings, separators=(',', ':'))}"
        )

        response = await client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.2,
            max_tokens=4096,
        )

        raw = response.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()

        return json.loads(raw)
    except Exception as exc:
        logger.error("AI triage failed: %s", exc)
        return {
            "summary": "AI triage unavailable at this time.",
            "findings": [],
            "_error": str(exc),
        }
