import logging
from app.scanners.base import BaseScanner, ScanResult
from app.config import settings

logger = logging.getLogger(__name__)


class GCPScanner(BaseScanner):
    name = "gcp"
    display_name = "Google Cloud Platform"

    async def scan(self, target: str, config: dict) -> ScanResult:
        result = ScanResult()
        if not settings.gcp_project_id:
            logger.warning("GCP scanner: no project configured")
            return result
        try:
            from google.cloud import aiplatform
            aiplatform.init(project=settings.gcp_project_id)
            endpoints = aiplatform.Endpoint.list()
            for ep in endpoints:
                result.assets.append({
                    "name": ep.display_name,
                    "asset_type": "model_server",
                    "provider": "gcp",
                    "endpoint_url": ep.resource_name,
                    "metadata_": {"resource_name": ep.resource_name},
                    "risk_score": 30,
                })
        except Exception as e:
            logger.error(f"GCP scan failed: {e}")
        return result
