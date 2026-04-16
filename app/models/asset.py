import uuid
import enum
from datetime import datetime
from sqlalchemy import String, DateTime, Integer, JSON, Enum as SAEnum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class AssetType(str, enum.Enum):
    k8s_pod = "k8s_pod"
    k8s_service = "k8s_service"
    k8s_deployment = "k8s_deployment"
    llm_api_endpoint = "llm_api_endpoint"
    mcp_server = "mcp_server"
    model_server = "model_server"
    saas_ai_tool = "saas_ai_tool"
    agentic_framework = "agentic_framework"
    cloud_ai_service = "cloud_ai_service"
    unknown = "unknown"


class AIAsset(Base):
    __tablename__ = "ai_assets"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String, nullable=False)
    asset_type: Mapped[AssetType] = mapped_column(SAEnum(AssetType), default=AssetType.unknown)
    provider: Mapped[str] = mapped_column(String, nullable=False)  # k8s, aws, gcp, azure, ibm, alibaba
    namespace: Mapped[str | None] = mapped_column(String, nullable=True)
    cluster: Mapped[str | None] = mapped_column(String, nullable=True)
    endpoint_url: Mapped[str | None] = mapped_column(String, nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    scan_run_id: Mapped[str | None] = mapped_column(String, ForeignKey("scan_runs.id"), nullable=True)
