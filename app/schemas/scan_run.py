from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict
from app.models.scan_run import ScanStatus


class ScanRunOut(BaseModel):
    id: str
    scanner_name: str
    status: ScanStatus
    target: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    asset_count: int = 0
    threat_count: int = 0
    vuln_count: int = 0
    error_message: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ScanTriggerRequest(BaseModel):
    scanner: str
    target: str
