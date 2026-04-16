import logging
from app.scanners.base import BaseScanner, ScanResult
from app.config import settings

logger = logging.getLogger(__name__)


class AWSScanner(BaseScanner):
    name = "aws"
    display_name = "Amazon Web Services"

    async def scan(self, target: str, config: dict) -> ScanResult:
        result = ScanResult()
        if not settings.aws_access_key_id:
            logger.warning("AWS scanner: no credentials configured")
            return result
        try:
            import boto3
            session = boto3.Session(
                aws_access_key_id=settings.aws_access_key_id,
                aws_secret_access_key=settings.aws_secret_access_key,
                region_name=settings.aws_region,
            )
            # SageMaker endpoints
            sm = session.client("sagemaker")
            endpoints = sm.list_endpoints().get("Endpoints", [])
            for ep in endpoints:
                result.assets.append({
                    "name": ep["EndpointName"],
                    "asset_type": "model_server",
                    "provider": "aws",
                    "endpoint_url": f"https://runtime.sagemaker.{settings.aws_region}.amazonaws.com/endpoints/{ep['EndpointName']}",
                    "metadata_": {"status": ep.get("EndpointStatus"), "creation_time": str(ep.get("CreationTime", ""))},
                    "risk_score": 30,
                })
            # Bedrock foundation models in use
            bedrock = session.client("bedrock", region_name=settings.aws_region)
            try:
                models = bedrock.list_foundation_models().get("modelSummaries", [])
                for m in models[:10]:
                    result.assets.append({
                        "name": m.get("modelId", "unknown"),
                        "asset_type": "cloud_ai_service",
                        "provider": "aws",
                        "metadata_": {"provider_name": m.get("providerName"), "modalities": m.get("inputModalities", [])},
                        "risk_score": 20,
                    })
            except Exception:
                pass
        except Exception as e:
            logger.error(f"AWS scan failed: {e}")
        return result
