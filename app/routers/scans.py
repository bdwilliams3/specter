import asyncio
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db, AsyncSessionLocal
from app.models.scan_run import ScanRun
from app.schemas.scan_run import ScanRunOut, ScanTriggerRequest
from app.services.scan_service import run_scan
from app.scanners import list_scanners
from app.auth.dependencies import get_current_user

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("/trigger", response_model=dict, status_code=202)
async def trigger_scan(
    body: ScanTriggerRequest,
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(get_current_user),
):
    available = [s["name"] for s in list_scanners()]
    if body.scanner not in available:
        raise HTTPException(status_code=400, detail=f"Scanner '{body.scanner}' not found. Available: {available}")

    # Run in background so we can return 202 immediately
    async def _run():
        async with AsyncSessionLocal() as session:
            await run_scan(body.scanner, body.target, session)

    asyncio.create_task(_run())
    return {"message": "Scan triggered", "scanner": body.scanner, "target": body.target}


@router.get("", response_model=list[ScanRunOut])
async def list_scans(db: AsyncSession = Depends(get_db), _user: dict = Depends(get_current_user)):
    result = await db.execute(select(ScanRun).order_by(ScanRun.started_at.desc()).limit(100))
    return [ScanRunOut.model_validate(r) for r in result.scalars().all()]


@router.get("/scanners")
async def get_scanners(_user: dict = Depends(get_current_user)):
    return list_scanners()


@router.get("/{scan_id}", response_model=ScanRunOut)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db), _user: dict = Depends(get_current_user)):
    result = await db.execute(select(ScanRun).where(ScanRun.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanRunOut.model_validate(scan)
