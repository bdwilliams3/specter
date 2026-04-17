from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timedelta
from app.database import get_db
from app.models.threat import ThreatEvent
from app.schemas.threat import ThreatOut
from app.auth.dependencies import get_current_user
from app.detectors.registry import RULES, SUPPORTED_CLOUDS
from app.config import settings
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


@router.get("/clouds")
async def list_clouds(_user: dict = Depends(get_current_user)):
    return {"items": SUPPORTED_CLOUDS}


@router.get("/rules")
async def list_rules(
    cloud: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(get_current_user),
):
    rules = [r for r in RULES if not cloud or r["cloud"] == cloud]

    cutoff = datetime.utcnow() - timedelta(hours=settings.threat_retention_hours)
    fire_q = (
        select(
            ThreatEvent.threat_name,
            func.count(ThreatEvent.id).label("fires"),
            func.max(ThreatEvent.detected_at).label("last_fired"),
        )
        .where(ThreatEvent.detected_at >= cutoff)
        .group_by(ThreatEvent.threat_name)
    )
    fire_rows = (await db.execute(fire_q)).all()
    fires_by_name = {row.threat_name: row for row in fire_rows}

    items = []
    for r in rules:
        stat = fires_by_name.get(r["threat_name"])
        items.append({
            **r,
            "fires_window": int(stat.fires) if stat else 0,
            "last_fired_at": stat.last_fired.isoformat() + "Z" if stat and stat.last_fired else None,
        })

    return {"total": len(items), "items": items}


@router.get("/{threat_id}", response_model=ThreatOut)
async def get_threat(threat_id: str, db: AsyncSession = Depends(get_db), _user: dict = Depends(get_current_user)):
    result = await db.execute(select(ThreatEvent).where(ThreatEvent.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return ThreatOut.model_validate(threat)
