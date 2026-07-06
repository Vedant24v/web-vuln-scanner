import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Boolean, Text, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
import enum

from backend.database import Base


class JobStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(
        SAEnum(JobStatus, name="job_status_enum", create_type=False),
        default=JobStatus.pending,
        nullable=False,
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    consent_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    requester_ip: Mapped[str] = mapped_column(String(64), nullable=True)
    consent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_message: Mapped[str] = mapped_column(Text, nullable=True)

    # AI triage result (stored as JSON text)
    ai_triage_json: Mapped[str] = mapped_column(Text, nullable=True)

    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="job", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=True)
    remediation: Mapped[str] = mapped_column(Text, nullable=True)

    job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="findings")
