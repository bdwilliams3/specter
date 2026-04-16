import uuid
import enum
from sqlalchemy import String, JSON, Enum as SAEnum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class RelationType(str, enum.Enum):
    api_call = "api_call"
    data_flow = "data_flow"
    orchestrates = "orchestrates"
    trusts = "trusts"
    network_peer = "network_peer"
    mcp_tool = "mcp_tool"


class TrustLevel(str, enum.Enum):
    high = "high"
    medium = "medium"
    low = "low"
    untrusted = "untrusted"


class AssetConnection(Base):
    __tablename__ = "asset_connections"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    source_id: Mapped[str] = mapped_column(String, ForeignKey("ai_assets.id"), nullable=False)
    target_id: Mapped[str] = mapped_column(String, ForeignKey("ai_assets.id"), nullable=False)
    relation_type: Mapped[RelationType] = mapped_column(SAEnum(RelationType))
    label: Mapped[str | None] = mapped_column(String, nullable=True)
    trust_level: Mapped[TrustLevel] = mapped_column(SAEnum(TrustLevel), default=TrustLevel.medium)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    scan_run_id: Mapped[str | None] = mapped_column(String, ForeignKey("scan_runs.id"), nullable=True)
