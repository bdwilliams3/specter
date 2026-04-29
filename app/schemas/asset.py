from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field
from app.models.asset import AssetType


class AssetBase(BaseModel):
    name: str
    asset_type: AssetType
    provider: str
    namespace: Optional[str] = None
    cluster: Optional[str] = None
    endpoint_url: Optional[str] = None
    metadata_: dict = Field(default_factory=dict)
    ai_confidence: float = 0.0
    triage_state: Optional[str] = None
    triage_reason: Optional[str] = None
    confidence_ceiling: Optional[float] = None
    triage_updated_by: Optional[str] = None
    triage_updated_at: Optional[datetime] = None
    risk_score: int = 0


class AssetCreate(AssetBase):
    pass


class AssetOut(AssetBase):
    id: str
    first_seen: datetime
    last_seen: datetime
    scan_run_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
