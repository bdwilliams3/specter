from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.database import get_db
from app.models.asset import AIAsset
from app.models.threat import ThreatEvent, ThreatSeverity
from app.models.vulnerability import Vulnerability, VulnSeverity
from app.models.scan_run import ScanRun
from app.auth.dependencies import get_current_user

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@router.get("")
async def get_metrics(db: AsyncSession = Depends(get_db), _user: dict = Depends(get_current_user)):
    total_assets = (await db.execute(select(func.count()).select_from(AIAsset))).scalar_one()
    total_threats = (await db.execute(select(func.count()).select_from(ThreatEvent))).scalar_one()
    total_vulns = (await db.execute(select(func.count()).select_from(Vulnerability))).scalar_one()

    # Threats by severity
    threats_by_severity = {}
    for sev in ThreatSeverity:
        count = (await db.execute(
            select(func.count()).select_from(ThreatEvent).where(ThreatEvent.severity == sev)
        )).scalar_one()
        threats_by_severity[sev.value] = count

    # Vulns by severity
    vulns_by_severity = {}
    for sev in VulnSeverity:
        count = (await db.execute(
            select(func.count()).select_from(Vulnerability).where(Vulnerability.severity == sev)
        )).scalar_one()
        vulns_by_severity[sev.value] = count

    # Assets by provider
    assets_by_provider_rows = (await db.execute(
        select(AIAsset.provider, func.count()).group_by(AIAsset.provider)
    )).all()
    assets_by_provider = {row[0]: row[1] for row in assets_by_provider_rows}

    # Last scan
    last_scan = (await db.execute(
        select(ScanRun).order_by(ScanRun.started_at.desc()).limit(1)
    )).scalar_one_or_none()

    return {
        "total_assets": total_assets,
        "total_threats": total_threats,
        "total_vulnerabilities": total_vulns,
        "threats_by_severity": threats_by_severity,
        "vulnerabilities_by_severity": vulns_by_severity,
        "assets_by_provider": assets_by_provider,
        "last_scan": {
            "id": last_scan.id,
            "scanner": last_scan.scanner_name,
            "status": last_scan.status,
            "started_at": last_scan.started_at.isoformat(),
        } if last_scan else None,
    }
