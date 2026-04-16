from typing import Optional
from pydantic import BaseModel, ConfigDict, Field
from app.models.connection import RelationType, TrustLevel


class ConnectionOut(BaseModel):
    id: str
    source_id: str
    target_id: str
    relation_type: RelationType
    label: Optional[str] = None
    trust_level: TrustLevel
    metadata_: dict = Field(default_factory=dict)
    scan_run_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
