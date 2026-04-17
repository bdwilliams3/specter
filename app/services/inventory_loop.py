"""
AI workload inventory loop.

The detection engine gates every rule on whether an audit event's target is a
known AI workload. The `k8s_mcp` scanner is what makes that determination —
inspecting pods, services, and deployments for LLM env vars, AI ports, and
known images, then writing the result to `ai_assets`.

This loop runs that scanner on a cadence so the inventory stays fresh without
requiring a manual `/api/scans/trigger` call. Without it, a newly-created AI
pod would not be visible to the rule engine until the next manual scan.
"""
import asyncio
import logging

from app.config import settings
from app.database import AsyncSessionLocal
from app.services.scan_service import run_scan

logger = logging.getLogger(__name__)


async def inventory_loop():
    interval = settings.inventory_interval_minutes * 60
    logger.info(
        "Inventory loop started — scanner=k8s_mcp, interval=%dm",
        settings.inventory_interval_minutes,
    )

    # Run once on startup so the initial inventory is populated before the
    # first hour elapses. Delay briefly so the DB and k8s client are ready.
    await asyncio.sleep(15)

    while True:
        try:
            async with AsyncSessionLocal() as session:
                scan = await run_scan("k8s_mcp", target="in-cluster", db=session)
                logger.info(
                    "Inventory scan %s finished: status=%s assets=%d",
                    scan.id, scan.status.value, scan.asset_count or 0,
                )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("Inventory scan cycle failed: %s", e)
        await asyncio.sleep(interval)
