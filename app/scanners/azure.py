import logging
from app.scanners.base import BaseScanner, ScanResult
from app.config import settings

logger = logging.getLogger(__name__)

# Cognitive Services kinds that are AI workloads
AI_COGNITIVE_KINDS = {
    "OpenAI",
    "AIServices",
    "CognitiveServices",
    "ComputerVision",
    "Face",
    "SpeechServices",
    "TextAnalytics",
    "TextTranslation",
    "FormRecognizer",
    "AnomalyDetector",
    "ContentModerator",
    "Personalizer",
    "LUIS",
    "QnAMaker",
    "ImmersiveReader",
    "BingSearch.v7",
    "BingCustomSearch",
    "BingVisualSearch",
    "BingEntitySearch",
    "BingSpellCheck.v7",
    "BingAutosuggest.v7",
}

COGNITIVE_KIND_TYPES = {
    "OpenAI": "llm_api_endpoint",
    "AIServices": "llm_api_endpoint",
    "SpeechServices": "model_server",
    "ComputerVision": "model_server",
    "Face": "model_server",
    "TextAnalytics": "model_server",
    "FormRecognizer": "model_server",
}


def _cognitive_asset_type(kind: str) -> str:
    return COGNITIVE_KIND_TYPES.get(kind, "cloud_ai_service")


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
            cred = ClientSecretCredential(
                settings.azure_tenant_id,
                settings.azure_client_id,
                settings.azure_client_secret,
            )
        except Exception as e:
            logger.error(f"Azure credential init failed: {e}")
            return result

        sub = settings.azure_subscription_id

        # --- Cognitive Services (OpenAI, AIServices, Vision, Speech, etc.) ---
        try:
            from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
            cog_client = CognitiveServicesManagementClient(cred, sub)
            for account in cog_client.accounts.list():
                kind = account.kind or ""
                if not any(k in kind for k in AI_COGNITIVE_KINDS) and kind not in AI_COGNITIVE_KINDS:
                    continue
                props = account.properties
                endpoint = props.endpoint if props else None
                sku = account.sku.name if account.sku else None

                # Security posture signals
                public_network_access = (props.public_network_access or "Enabled") if props else "Enabled"
                disable_local_auth = (props.disable_local_auth or False) if props else False
                network_acls = props.network_acls if props else None
                has_acl_rules = bool(
                    network_acls and (
                        getattr(network_acls, "ip_rules", None) or
                        getattr(network_acls, "virtual_network_rules", None)
                    )
                )
                private_endpoints = (props.private_endpoint_connections or []) if props else []
                has_private_endpoint = len(private_endpoints) > 0
                encryption = props.encryption if props else None
                has_cmk = bool(encryption and getattr(encryption, "key_source", None) == "Microsoft.KeyVault")

                result.assets.append({
                    "name": account.name,
                    "asset_type": _cognitive_asset_type(kind),
                    "provider": "azure",
                    "endpoint_url": endpoint,
                    "metadata_": {
                        "kind": kind,
                        "location": account.location,
                        "sku": sku,
                        "provisioning_state": props.provisioning_state if props else None,
                        "resource_group": _rg_from_id(account.id),
                        # security posture
                        "public_network_access": public_network_access,
                        "local_auth_enabled": not disable_local_auth,
                        "has_network_acls": has_acl_rules,
                        "has_private_endpoint": has_private_endpoint,
                        "has_cmk_encryption": has_cmk,
                    },
                    "risk_score": 40 if kind == "OpenAI" else 30,
                })
            logger.info(f"Azure CognitiveServices: found {len(result.assets)} accounts")
        except Exception as e:
            logger.error(f"Azure CognitiveServices scan failed: {e}")

        # --- Azure Machine Learning workspaces ---
        ml_assets = []
        try:
            from azure.mgmt.machinelearningservices import MachineLearningServicesMgmtClient
            ml_client = MachineLearningServicesMgmtClient(cred, sub)
            for ws in ml_client.workspaces.list_by_subscription():
                ml_assets.append({
                    "name": ws.name,
                    "asset_type": "cloud_ai_service",
                    "provider": "azure",
                    "endpoint_url": None,
                    "metadata_": {
                        "kind": "MachineLearningWorkspace",
                        "location": ws.location,
                        "resource_group": _rg_from_id(ws.id),
                        "sku": ws.sku.name if ws.sku else None,
                    },
                    "risk_score": 35,
                })
            logger.info(f"Azure ML: found {len(ml_assets)} workspaces")
            result.assets.extend(ml_assets)
        except Exception as e:
            logger.error(f"Azure ML scan failed: {e}")

        logger.info(f"Azure scan complete: {len(result.assets)} AI assets")
        return result


def _rg_from_id(resource_id: str | None) -> str:
    """Extract resource group name from Azure resource ID."""
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return ""
