import logging
from app.scanners.base import BaseScanner, ScanResult
from app.config import settings

logger = logging.getLogger(__name__)


class AlibabaScanner(BaseScanner):
    name = "alibaba"
    display_name = "Alibaba Cloud"

    async def scan(self, target: str, config: dict) -> ScanResult:
        result = ScanResult()
        if not settings.alibaba_access_key_id:
            logger.warning("Alibaba scanner: no credentials configured")
            return result
        try:
            # alibabacloud-tea-openapi for PAI / Model Studio
            result.assets.append({
                "name": "alibaba-pai-placeholder",
                "asset_type": "cloud_ai_service",
                "provider": "alibaba",
                "metadata_": {"region": settings.alibaba_region_id, "note": "Alibaba scanner configured"},
                "risk_score": 20,
            })
        except Exception as e:
            logger.error(f"Alibaba scan failed: {e}")
        return result
