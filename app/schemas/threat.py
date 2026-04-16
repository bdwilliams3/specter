from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field
from app.models.threat import ThreatSeverity, ThreatCategory


class ThreatBase(BaseModel):
    asset_id: Optional[str] = None
    title: str
    description: str
    severity: ThreatSeverity
    category: ThreatCategory
    raw_evidence: dict = Field(default_factory=dict)
    mitre_atlas: Optional[str] = None


class ThreatOut(ThreatBase):
    id: str
    detected_at: datetime
    scan_run_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
