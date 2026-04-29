import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Float, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class AIAssetSignal(Base):
    __tablename__ = "ai_signals"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(String, ForeignKey("ai_assets.id"), nullable=False, index=True)
    signal_type: Mapped[str] = mapped_column(String, nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False)
    value: Mapped[str] = mapped_column(String, nullable=False)
    weight: Mapped[float] = mapped_column(Float, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    ttl_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
