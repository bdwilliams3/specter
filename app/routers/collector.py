"""
POST /api/collector/k8s/audit — receives audit event batches from the Specter Collector agent.

Accepts three payload shapes:
  - {"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[...]}  (kube-apiserver direct)
  - {"items":[...], "cluster":"name"}                                   (collector forwarded)
  - [...]                                                                (raw list)
"""
import logging
from fastapi import APIRouter, Request, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.services.audit_service import process_audit_events
from app.services.network_service import process_network_events

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/collector", tags=["collector"])


@router.post("/k8s/audit", status_code=200)
async def receive_audit_events(request: Request, db: AsyncSession = Depends(get_db)):
    payload = await request.json()

    if isinstance(payload, list):
        events = payload
        cluster = None
    elif payload.get("kind") == "EventList":
        events = payload.get("items", [])
        cluster = None
    elif payload.get("kind") == "Event":
        events = [payload]
        cluster = None
    else:
        # Collector-forwarded format: {"items": [...], "cluster": "name"}
        events = payload.get("items", [])
        cluster = payload.get("cluster")

    if cluster:
        logger.info("Collector received %d events from cluster '%s'", len(events), cluster)

    count = await process_audit_events(events, db)
    return {"received": len(events), "threats_fired": count}


@router.post("/k8s/network", status_code=200)
async def receive_network_events(request: Request, db: AsyncSession = Depends(get_db)):
    """Receives Tetragon eBPF network events from the Specter Collector agent."""
    payload = await request.json()
    events  = payload.get("items", [])
    cluster = payload.get("cluster")

    if cluster:
        logger.info("Network events from cluster '%s': %d events", cluster, len(events))

    count = await process_network_events(events, db)
    return {"received": len(events), "threats_fired": count}
