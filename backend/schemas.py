from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, HttpUrl, field_validator


class ScanRequest(BaseModel):
    target: str
    consent_confirmed: bool

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("Target must start with http:// or https://")
        return v

    @field_validator("consent_confirmed")
    @classmethod
    def consent_must_be_true(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "You must confirm you own or have explicit written authorization to test this target."
            )
        return v


class FindingOut(BaseModel):
    id: str
    job_id: str
    category: str
    severity: str
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None

    model_config = {"from_attributes": True}


class AITriageFinding(BaseModel):
    priority_rank: int
    category: str
    severity: str
    business_risk: str
    remediation: str
    related_raw_ids: List[str] = []


class AITriageOut(BaseModel):
    summary: str
    findings: List[AITriageFinding]


class ScanJobOut(BaseModel):
    id: str
    target: str
    status: str
    requested_at: datetime
    consent_confirmed: bool
    requester_ip: Optional[str] = None
    consent_at: Optional[datetime] = None
    error_message: Optional[str] = None
    findings: List[FindingOut] = []
    ai_triage: Optional[Any] = None

    model_config = {"from_attributes": True}
