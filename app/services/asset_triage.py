from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import AIAsset
from app.models.asset_triage import AssetTriageAudit


def effective_confidence(asset: AIAsset) -> float:
    confidence = float(asset.ai_confidence or 0.0)
    if asset.confidence_ceiling is not None:
        confidence = min(confidence, float(asset.confidence_ceiling))
    return confidence


def triage_snapshot(asset: AIAsset) -> dict:
    return {
        "triage_state": asset.triage_state,
        "triage_reason": asset.triage_reason,
        "confidence_ceiling": asset.confidence_ceiling,
        "triage_updated_by": asset.triage_updated_by,
        "triage_updated_at": asset.triage_updated_at.isoformat() if asset.triage_updated_at else None,
    }


async def apply_asset_triage(db: AsyncSession, asset: AIAsset, action: str, reason: str,
                             updated_by: str, confidence_ceiling: float | None = None) -> AIAsset:
    before = triage_snapshot(asset)
    now = datetime.utcnow()
    if action == "confirm":
        asset.triage_state = "confirmed"
        asset.confidence_ceiling = None
    elif action == "downgrade":
        asset.triage_state = "downgraded"
        asset.confidence_ceiling = confidence_ceiling if confidence_ceiling is not None else 5.0
    elif action == "dismiss":
        asset.triage_state = "dismissed"
    else:
        raise ValueError("Unsupported triage action")

    asset.triage_reason = reason
    asset.triage_updated_by = updated_by
    asset.triage_updated_at = now
    after = triage_snapshot(asset)
    db.add(
        AssetTriageAudit(
            asset_id=asset.id,
            action=action,
            reason=reason,
            updated_by=updated_by,
            before=before,
            after=after,
        )
    )
    await db.commit()
    await db.refresh(asset)
    return asset
