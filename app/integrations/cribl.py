import httpx
import logging
from app.config import settings

logger = logging.getLogger(__name__)


async def send_event(data: dict) -> bool:
    if not settings.cribl_url:
        return False
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(settings.cribl_url, json=data, timeout=10)
            return resp.status_code < 300
    except Exception as e:
        logger.error(f"Cribl push failed: {e}")
        return False


async def test_connection() -> dict:
    ok = await send_event({"test": True, "source": "specter"})
    return {"ok": ok, "integration": "cribl"}
