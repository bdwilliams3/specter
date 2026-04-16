"""
Processes k8s audit event batches: enrich, evaluate rules, persist threats, broadcast.
Called by both the webhook collector and the log-tail scanner.
"""
import logging
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import AIAsset
from app.models.threat import ThreatEvent, ThreatSeverity, ThreatCategory
from app.detectors.threat_rules import evaluate
from app.services.ws_manager import ws_manager as manager

logger = logging.getLogger(__name__)


async def process_audit_events(events: list[dict], db: AsyncSession, scan_run_id: str | None = None) -> int:
    """
    Process a batch of k8s audit events.
    Returns the number of new threats persisted.
    """
    if not events:
        return 0

    # Load AI asset names for enrichment (used to bump severity)
    result = await db.execute(select(AIAsset.name, AIAsset.id))
    rows = result.all()
    ai_asset_names = {r.name for r in rows}
    name_to_id = {r.name: r.id for r in rows}

    # Load already-processed audit IDs to deduplicate
    audit_ids = [e.get("auditID") for e in events if e.get("auditID")]
    existing = set()
    if audit_ids:
        res = await db.execute(
            select(ThreatEvent.audit_id).where(ThreatEvent.audit_id.in_(audit_ids))
        )
        existing = {r[0] for r in res.all()}

    new_threats = 0
    for event in events:
        aid = event.get("auditID")
        if aid and aid in existing:
            continue

        threat_dict = evaluate(event, ai_asset_names)
        if not threat_dict:
            continue

        # Correlate to an asset if possible
        obj_name = event.get("objectRef", {}).get("name", "")
        asset_id = name_to_id.get(obj_name)

        try:
            threat_name = threat_dict["threat_name"]
            threat = ThreatEvent(
                asset_id=asset_id,
                threat_name=threat_name,
                title=threat_name,
                description=threat_dict["description"],
                severity=ThreatSeverity(threat_dict["severity"]),
                category=ThreatCategory(threat_dict["category"]),
                principal_role=threat_dict.get("principal_role"),
                principal_subject=threat_dict.get("principal_subject"),
                method=threat_dict.get("method"),
                resource=threat_dict.get("resource"),
                namespace=threat_dict.get("namespace"),
                source_ips=threat_dict.get("source_ips"),
                raw_evidence=threat_dict.get("raw_evidence", {}),
                mitre_atlas=threat_dict.get("mitre_atlas"),
                audit_id=threat_dict.get("audit_id"),
                detected_at=datetime.utcnow(),
                scan_run_id=scan_run_id,
            )
            db.add(threat)
            await db.flush()
            new_threats += 1

            # Broadcast via WebSocket
            await manager.broadcast({
                "type": "threat",
                "id": threat.id,
                "title": threat.title,
                "severity": threat.severity.value,
                "category": threat.category.value,
                "detected_at": threat.detected_at.isoformat(),
            })

            if aid:
                existing.add(aid)

        except Exception as e:
            logger.warning("Failed to persist threat: %s", e)

    if new_threats:
        await db.commit()
        logger.info("Persisted %d new threats from %d audit events", new_threats, len(events))

    return new_threats
