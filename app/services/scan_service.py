import uuid
import logging
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from app.models.scan_run import ScanRun, ScanStatus
from app.models.asset import AIAsset
from app.models.threat import ThreatEvent
from app.models.vulnerability import Vulnerability
from app.models.connection import AssetConnection
from app.scanners import get_scanner
from app.detectors import vuln_detector
from app.services.asset_scoring import calculate_ai_confidence, replace_asset_signals
from app.services.ws_manager import ws_manager

logger = logging.getLogger(__name__)


async def run_scan(scanner_name: str, target: str, db: AsyncSession) -> ScanRun:
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
        result = vuln_detector.analyze(result, {})

        now = datetime.utcnow()

        # --- Reconcile assets ---
        # Key: (scanner_name, name, namespace)
        incoming_asset_keys = {
            (scanner_name, a["name"], a.get("namespace", "")) for a in result.assets
        }

        existing_assets_q = await db.execute(
            select(AIAsset).where(AIAsset.scan_run_id.in_(
                select(ScanRun.id).where(ScanRun.scanner_name == scanner_name)
            ))
        )
        existing_assets = {
            (scanner_name, a.name, a.namespace or ""): a
            for a in existing_assets_q.scalars().all()
        }

        # Delete assets not in current scan
        stale_asset_keys = set(existing_assets.keys()) - incoming_asset_keys
        for key in stale_asset_keys:
            await db.delete(existing_assets[key])

        # Upsert assets
        asset_name_to_id: dict[str, str] = {}
        assets_for_signals: list[tuple[AIAsset, list[dict]]] = []
        for a in result.assets:
            key = (scanner_name, a["name"], a.get("namespace", ""))
            ai_signals = a.get("ai_signals", [])
            ai_confidence = calculate_ai_confidence(ai_signals)
            if key in existing_assets:
                # Update last_seen and risk_score
                existing = existing_assets[key]
                existing.last_seen = now
                existing.risk_score = a.get("risk_score", existing.risk_score)
                existing.ai_confidence = ai_confidence
                existing.metadata_ = a.get("metadata_", existing.metadata_)
                existing.scan_run_id = scan_run.id
                asset_name_to_id[a["name"]] = existing.id
                assets_for_signals.append((existing, ai_signals))
            else:
                asset = AIAsset(
                    id=str(uuid.uuid4()),
                    scan_run_id=scan_run.id,
                    first_seen=now,
                    last_seen=now,
                    ai_confidence=ai_confidence,
                    **{k: v for k, v in a.items() if k not in ("metadata_", "ai_signals")},
                    metadata_=a.get("metadata_", {}),
                )
                db.add(asset)
                asset_name_to_id[a["name"]] = asset.id
                assets_for_signals.append((asset, ai_signals))

        await db.flush()
        for asset, ai_signals in assets_for_signals:
            await replace_asset_signals(db, asset, ai_signals, source_prefix=scanner_name.split("_")[0])

        # --- Reconcile vulnerabilities ---
        # Key: (scanner_name, category, asset_name)
        incoming_vuln_keys = {
            (scanner_name, v["category"], v.get("asset_name", ""))
            for v in result.vulnerabilities
        }

        existing_vulns_q = await db.execute(
            select(Vulnerability).where(Vulnerability.scanner_name == scanner_name)
        )
        existing_vulns = {
            (v.scanner_name, v.category, v.asset_name): v
            for v in existing_vulns_q.scalars().all()
        }

        # Delete vulns not in current scan
        stale_vuln_keys = set(existing_vulns.keys()) - incoming_vuln_keys
        for key in stale_vuln_keys:
            await db.delete(existing_vulns[key])

        # Upsert vulns
        for v in result.vulnerabilities:
            asset_name = v.get("asset_name", "")
            key = (scanner_name, v["category"], asset_name)
            if key in existing_vulns:
                existing = existing_vulns[key]
                existing.last_seen = now
                existing.scan_run_id = scan_run.id
                existing.description = v.get("description", existing.description)
            else:
                vuln = Vulnerability(
                    id=str(uuid.uuid4()),
                    scan_run_id=scan_run.id,
                    scanner_name=scanner_name,
                    asset_name=asset_name,
                    asset_id=asset_name_to_id.get(asset_name),
                    first_seen=now,
                    last_seen=now,
                    **{k: v2 for k, v2 in v.items() if k not in ("asset_name",)},
                )
                db.add(vuln)
                await ws_manager.broadcast({"event": "new_vuln", "severity": v.get("severity"), "title": v.get("title")})

        # --- Threats: append only ---
        for t in result.threats:
            threat = ThreatEvent(
                id=str(uuid.uuid4()),
                scan_run_id=scan_run.id,
                asset_id=asset_name_to_id.get(t.get("asset_name", "")),
                **{k: v for k, v in t.items() if k not in ("raw_evidence", "asset_name")},
                raw_evidence=t.get("raw_evidence", {}),
            )
            db.add(threat)
            await ws_manager.broadcast({"event": "new_threat", "severity": t.get("severity"), "title": t.get("title")})

        scan_run.status = ScanStatus.success
        scan_run.finished_at = datetime.utcnow()
        scan_run.asset_count = len(result.assets)
        scan_run.threat_count = len(result.threats)
        scan_run.vuln_count = len(result.vulnerabilities)
        await db.commit()
        await ws_manager.broadcast({
            "event": "scan_complete", "scan_id": scan_run.id,
            "assets": scan_run.asset_count, "threats": scan_run.threat_count,
            "vulns": scan_run.vuln_count,
        })

    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        scan_run.status = ScanStatus.failed
        scan_run.error_message = str(e)
        scan_run.finished_at = datetime.utcnow()
        await db.commit()

    return scan_run
