from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.database import get_db
from app.models.asset import AIAsset, AssetType
from app.models.asset_signal import AIAssetSignal
from app.schemas.asset import AssetOut
from app.auth.dependencies import get_current_user
from app.services.asset_triage import apply_asset_triage
from typing import Optional
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/assets", tags=["assets"])


class AssetTriagePatch(BaseModel):
    action: str
    reason: str = Field(min_length=3)
    confidence_ceiling: float | None = Field(default=None, ge=0, le=10)


def _actor(user: dict) -> str:
    return user.get("email") or user.get("sub") or "unknown"


@router.get("", response_model=dict)
async def list_assets(
    asset_type: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(get_current_user),
):
    q = select(AIAsset)
    if asset_type:
        q = q.where(AIAsset.asset_type == asset_type)
    if provider:
        q = q.where(AIAsset.provider == provider)

    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar_one()

    q = q.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    assets = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [AssetOut.model_validate(a).model_dump() for a in assets],
    }


@router.get("/{asset_id}", response_model=AssetOut)
async def get_asset(asset_id: str, db: AsyncSession = Depends(get_db), _user: dict = Depends(get_current_user)):
    result = await db.execute(select(AIAsset).where(AIAsset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return AssetOut.model_validate(asset)


@router.get("/{asset_id}/signals")
async def get_asset_signals(asset_id: str, db: AsyncSession = Depends(get_db), _user: dict = Depends(get_current_user)):
    result = await db.execute(select(AIAsset).where(AIAsset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    signals_result = await db.execute(
        select(AIAssetSignal)
        .where(AIAssetSignal.asset_id == asset_id)
        .order_by(AIAssetSignal.observed_at.desc())
    )
    signals = signals_result.scalars().all()
    return {
        "asset_id": asset.id,
        "ai_confidence": asset.ai_confidence,
        "items": [
            {
                "id": signal.id,
                "signal_type": signal.signal_type,
                "source": signal.source,
                "value": signal.value,
                "weight": signal.weight,
                "observed_at": signal.observed_at.isoformat() if signal.observed_at else None,
                "ttl_expires_at": signal.ttl_expires_at.isoformat() if signal.ttl_expires_at else None,
            }
            for signal in signals
        ],
    }


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(asset_id: str, db: AsyncSession = Depends(get_db), _user: dict = Depends(get_current_user)):
    result = await db.execute(select(AIAsset).where(AIAsset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    await db.delete(asset)
    await db.commit()


@router.patch("/{asset_id}/triage", response_model=AssetOut)
async def triage_asset(
    asset_id: str,
    patch: AssetTriagePatch,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    result = await db.execute(select(AIAsset).where(AIAsset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    try:
        updated = await apply_asset_triage(
            db,
            asset,
            patch.action,
            patch.reason,
            _actor(user),
            patch.confidence_ceiling,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AssetOut.model_validate(updated)
