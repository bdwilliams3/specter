from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.database import get_db
from app.models.threat import ThreatEvent
from app.schemas.threat import ThreatOut
from app.auth.dependencies import get_current_user
from typing import Optional

router = APIRouter(prefix="/api/threats", tags=["threats"])


@router.get("", response_model=dict)
async def list_threats(
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(get_current_user),
):
    q = select(ThreatEvent).order_by(ThreatEvent.detected_at.desc())
    if severity:
        q = q.where(ThreatEvent.severity == severity)
    if category:
        q = q.where(ThreatEvent.category == category)

    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar_one()

    q = q.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    threats = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [ThreatOut.model_validate(t).model_dump() for t in threats],
    }


@router.get("/{threat_id}", response_model=ThreatOut)
async def get_threat(threat_id: str, db: AsyncSession = Depends(get_db), _user: dict = Depends(get_current_user)):
    result = await db.execute(select(ThreatEvent).where(ThreatEvent.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return ThreatOut.model_validate(threat)
