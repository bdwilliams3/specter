import uuid
import enum
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean, JSON, Enum as SAEnum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class ThreatSeverity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ThreatCategory(str, enum.Enum):
    prompt_injection = "prompt_injection"
    data_exfiltration = "data_exfiltration"
    model_abuse = "model_abuse"
    unauthorized_access = "unauthorized_access"
    anomalous_api_usage = "anomalous_api_usage"
    supply_chain = "supply_chain"
    availability = "availability"


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str | None] = mapped_column(String, ForeignKey("ai_assets.id"), nullable=True)
    threat_name: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)  # kept for backward compat, mirrors threat_name
    description: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[ThreatSeverity] = mapped_column(SAEnum(ThreatSeverity), default=ThreatSeverity.medium)
    category: Mapped[ThreatCategory] = mapped_column(SAEnum(ThreatCategory))
    # Structured principal / action fields — lets consumers filter without parsing raw_evidence
    principal_role: Mapped[str | None] = mapped_column(String, nullable=True)
    principal_subject: Mapped[str | None] = mapped_column(String, nullable=True)
    method: Mapped[str | None] = mapped_column(String, nullable=True)
    resource: Mapped[str | None] = mapped_column(String, nullable=True)
    namespace: Mapped[str | None] = mapped_column(String, nullable=True)
    source_ips: Mapped[list | None] = mapped_column(JSON, nullable=True)
    raw_evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    suppression_reason: Mapped[str | None] = mapped_column(String, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    scan_run_id: Mapped[str | None] = mapped_column(String, ForeignKey("scan_runs.id"), nullable=True)
    mitre_atlas: Mapped[str | None] = mapped_column(String, nullable=True)
    audit_id: Mapped[str | None] = mapped_column(String, nullable=True, unique=True, index=True)
