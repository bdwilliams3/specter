from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field
from app.models.threat import ThreatSeverity, ThreatCategory


class ThreatBase(BaseModel):
    """Retained for import compatibility."""
    threat_name: str = ""
    description: str = ""
    severity: ThreatSeverity = ThreatSeverity.medium
    category: ThreatCategory = ThreatCategory.unauthorized_access


class ThreatOut(BaseModel):
    event_id: str = Field(alias="id")
    threat_name: str
    description: str
    severity: ThreatSeverity
    category: ThreatCategory
    principal_role: Optional[str] = None
    principal_subject: Optional[str] = None
    method: Optional[str] = None
    resource: Optional[str] = None
    namespace: Optional[str] = None
    source_ips: Optional[list] = None
    mitre_atlas: Optional[str] = None
    asset_id: Optional[str] = None
    raw_evidence: dict = Field(default_factory=dict)
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    detected_at: datetime
    scan_run_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
