"""
Threat retention purge — Specter brokers detections, customers own long-term storage.

Runs as a background task in the FastAPI lifespan. Deletes any ThreatEvent older
than `settings.threat_retention_hours` on a fixed interval. No soft-delete, no
forwarded-marker check (yet) — TTL is hard until SIEM connectors land.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from sqlalchemy import delete

from app.config import settings
from app.database import AsyncSessionLocal
from app.models.threat import ThreatEvent

logger = logging.getLogger(__name__)


async def purge_expired_threats() -> int:
    cutoff = datetime.utcnow() - timedelta(hours=settings.threat_retention_hours)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            delete(ThreatEvent).where(ThreatEvent.detected_at < cutoff)
        )
        await session.commit()
        return result.rowcount or 0


async def retention_loop():
    interval = settings.threat_purge_interval_minutes * 60
    logger.info(
        "Threat retention loop started — TTL=%dh, interval=%dm",
        settings.threat_retention_hours, settings.threat_purge_interval_minutes,
    )
    while True:
        try:
            purged = await purge_expired_threats()
            if purged:
                logger.info(
                    "Purged %d threats older than %dh (TTL hard-cap)",
                    purged, settings.threat_retention_hours,
                )
        except Exception as e:
            logger.warning("Threat purge cycle failed: %s", e)
        await asyncio.sleep(interval)
