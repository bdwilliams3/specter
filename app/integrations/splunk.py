import httpx
import logging
from app.config import settings

logger = logging.getLogger(__name__)


async def send_event(data: dict) -> bool:
    if not settings.splunk_hec_url:
        return False
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                settings.splunk_hec_url,
                json={"event": data, "sourcetype": "specter:finding"},
                headers={"Authorization": f"Splunk {settings.splunk_hec_token}"},
                timeout=10,
            )
            return resp.status_code == 200
    except Exception as e:
        logger.error(f"Splunk push failed: {e}")
        return False


async def test_connection() -> dict:
    ok = await send_event({"test": True, "source": "specter"})
    return {"ok": ok, "integration": "splunk"}
