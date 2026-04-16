import httpx
import logging
import time
from app.config import settings

logger = logging.getLogger(__name__)


async def send_log(labels: dict, message: str) -> bool:
    if not settings.grafana_url:
        return False
    payload = {
        "streams": [{"stream": labels, "values": [[str(int(time.time() * 1e9)), message]]}]
    }
    try:
        async with httpx.AsyncClient() as client:
            headers = {}
            if settings.grafana_api_key:
                headers["Authorization"] = f"Bearer {settings.grafana_api_key}"
            resp = await client.post(settings.grafana_url, json=payload, headers=headers, timeout=10)
            return resp.status_code < 300
    except Exception as e:
        logger.error(f"Grafana push failed: {e}")
        return False


async def test_connection() -> dict:
    ok = await send_log({"app": "specter", "level": "info"}, "Specter connection test")
    return {"ok": ok, "integration": "grafana"}
