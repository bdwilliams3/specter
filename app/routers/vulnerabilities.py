from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, outerjoin
from app.database import get_db
from app.models.vulnerability import Vulnerability
from app.models.scan_run import ScanRun
from app.schemas.vulnerability import VulnOut
from app.auth.dependencies import get_current_user
from typing import Optional

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


def _enrich(v: Vulnerability, target: str | None) -> dict:
    d = VulnOut.model_validate(v).model_dump()
    d["scanner_name"] = v.scanner_name
    d["asset_name"] = v.asset_name
    d["last_seen"] = v.last_seen.isoformat() if v.last_seen else None
    d["cluster"] = target or v.scanner_name
    return d


@router.get("", response_model=dict)
async def list_vulns(
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(get_current_user),
):
    base = select(Vulnerability)
    if severity:
        base = base.where(Vulnerability.severity == severity)
    if category:
        base = base.where(Vulnerability.category == category)
    base = base.order_by(Vulnerability.first_seen.desc())

    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()

    j = (
        select(Vulnerability, ScanRun.target)
        .select_from(outerjoin(Vulnerability, ScanRun, Vulnerability.scan_run_id == ScanRun.id))
        .order_by(Vulnerability.first_seen.desc())
    )
    if severity:
        j = j.where(Vulnerability.severity == severity)
    if category:
        j = j.where(Vulnerability.category == category)
    j = j.offset((page - 1) * page_size).limit(page_size)

    rows = (await db.execute(j)).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [_enrich(v, target) for v, target in rows],
    }


@router.get("/{vuln_id}")
async def get_vuln(vuln_id: str, db: AsyncSession = Depends(get_db), _user: dict = Depends(get_current_user)):
    row = (await db.execute(
        select(Vulnerability, ScanRun.target)
        .select_from(outerjoin(Vulnerability, ScanRun, Vulnerability.scan_run_id == ScanRun.id))
        .where(Vulnerability.id == vuln_id)
    )).one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    v, target = row
    return _enrich(v, target)
