import uuid
import logging
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.scan_run import ScanRun, ScanStatus
from app.models.asset import AIAsset
from app.models.threat import ThreatEvent
from app.models.vulnerability import Vulnerability
from app.models.connection import AssetConnection
from app.scanners import get_scanner
from app.detectors import threat_detector, vuln_detector
from app.services.ws_manager import ws_manager
from app.config import settings

logger = logging.getLogger(__name__)


async def run_scan(scanner_name: str, target: str, db: AsyncSession) -> ScanRun:
    # Create scan run record
    scan_run = ScanRun(
        id=str(uuid.uuid4()),
        scanner_name=scanner_name,
        status=ScanStatus.running,
        target=target,
        started_at=datetime.utcnow(),
    )
    db.add(scan_run)
    await db.commit()

    await ws_manager.broadcast({"event": "scan_started", "scan_id": scan_run.id, "scanner": scanner_name})

    scanner = get_scanner(scanner_name)
    if not scanner:
        scan_run.status = ScanStatus.failed
        scan_run.error_message = f"Scanner '{scanner_name}' not found"
        scan_run.finished_at = datetime.utcnow()
        await db.commit()
        return scan_run

    try:
        result = await scanner.scan(target, {})
        result = threat_detector.analyze(result, {})
        result = vuln_detector.analyze(result, {})

        # Persist assets
        asset_db_map = {}
        for a in result.assets:
            asset = AIAsset(
                id=str(uuid.uuid4()),
                scan_run_id=scan_run.id,
                **{k: v for k, v in a.items() if k != "metadata_"},
                metadata_=a.get("metadata_", {}),
            )
            db.add(asset)
            asset_db_map[a["name"]] = asset.id

        # Persist threats
        for t in result.threats:
            threat = ThreatEvent(
                id=str(uuid.uuid4()),
                scan_run_id=scan_run.id,
                **{k: v for k, v in t.items() if k not in ("raw_evidence",)},
                raw_evidence=t.get("raw_evidence", {}),
            )
            db.add(threat)
            await ws_manager.broadcast({"event": "new_threat", "severity": t.get("severity"), "title": t.get("title")})

        # Persist vulnerabilities
        for v in result.vulnerabilities:
            vuln = Vulnerability(
                id=str(uuid.uuid4()),
                scan_run_id=scan_run.id,
                **v,
            )
            db.add(vuln)
            await ws_manager.broadcast({"event": "new_vuln", "severity": v.get("severity"), "title": v.get("title")})

        # Persist connections
        for c in result.connections:
            conn = AssetConnection(id=str(uuid.uuid4()), scan_run_id=scan_run.id, **c)
            db.add(conn)

        scan_run.status = ScanStatus.success
        scan_run.finished_at = datetime.utcnow()
        scan_run.asset_count = len(result.assets)
        scan_run.threat_count = len(result.threats)
        scan_run.vuln_count = len(result.vulnerabilities)
        await db.commit()
        await ws_manager.broadcast({"event": "scan_complete", "scan_id": scan_run.id,
                                    "assets": scan_run.asset_count, "threats": scan_run.threat_count,
                                    "vulns": scan_run.vuln_count})
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        scan_run.status = ScanStatus.failed
        scan_run.error_message = str(e)
        scan_run.finished_at = datetime.utcnow()
        await db.commit()

    return scan_run
