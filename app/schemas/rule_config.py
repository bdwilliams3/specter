from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


Severity = Literal["critical", "high", "medium", "low", "info"]


class RuleConfigPatch(BaseModel):
    min_asset_confidence: int | None = Field(default=None, ge=0, le=10)
    enabled: bool | None = None
    severity_override: Severity | None = None
    route: str | None = None


class RuleConfigBulkPatch(BaseModel):
    rule_id: str
    patch: RuleConfigPatch


class RuleConfigOut(BaseModel):
    rule_id: str
    min_asset_confidence: int
    enabled: bool
    severity_override: str | None = None
    route: str | None = None
    updated_by: str | None = None
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)
