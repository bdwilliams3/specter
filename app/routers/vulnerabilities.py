from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.database import get_db
from app.models.vulnerability import Vulnerability
from app.schemas.vulnerability import VulnOut
from app.auth.dependencies import get_current_user
from typing import Optional

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


@router.get("", response_model=dict)
async def list_vulns(
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(get_current_user),
):
    q = select(Vulnerability).order_by(Vulnerability.first_seen.desc())
    if severity:
        q = q.where(Vulnerability.severity == severity)
    if category:
        q = q.where(Vulnerability.category == category)

    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar_one()

    q = q.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    vulns = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [VulnOut.model_validate(v).model_dump() for v in vulns],
    }


@router.get("/{vuln_id}", response_model=VulnOut)
async def get_vuln(vuln_id: str, db: AsyncSession = Depends(get_db), _user: dict = Depends(get_current_user)):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return VulnOut.model_validate(vuln)
