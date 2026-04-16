import logging
from app.scanners.base import BaseScanner, ScanResult
from app.config import settings

logger = logging.getLogger(__name__)


class AzureScanner(BaseScanner):
    name = "azure"
    display_name = "Microsoft Azure"

    async def scan(self, target: str, config: dict) -> ScanResult:
        result = ScanResult()
        if not settings.azure_subscription_id:
            logger.warning("Azure scanner: no subscription configured")
            return result
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
            cred = ClientSecretCredential(settings.azure_tenant_id, settings.azure_client_id, settings.azure_client_secret)
            client = CognitiveServicesManagementClient(cred, settings.azure_subscription_id)
            for account in client.accounts.list():
                if "OpenAI" in (account.kind or ""):
                    result.assets.append({
                        "name": account.name,
                        "asset_type": "llm_api_endpoint",
                        "provider": "azure",
                        "endpoint_url": account.properties.endpoint if account.properties else None,
                        "metadata_": {"kind": account.kind, "location": account.location},
                        "risk_score": 35,
                    })
        except Exception as e:
            logger.error(f"Azure scan failed: {e}")
        return result
