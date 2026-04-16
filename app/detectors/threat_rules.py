import logging
from app.detectors.base import BaseDetector
from app.scanners.base import ScanResult

logger = logging.getLogger(__name__)

SENSITIVE_ENV_VARS = [
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "HF_TOKEN",
    "AWS_SECRET_ACCESS_KEY", "AZURE_OPENAI_API_KEY", "IBM_API_KEY",
]


class ThreatDetector(BaseDetector):
    def analyze(self, result: ScanResult, raw_context: dict) -> ScanResult:
        assets = result.assets
        for asset in assets:
            meta = asset.get("metadata_", {})
            # Detect API keys exposed in pod metadata (from env var fingerprinting)
            if meta.get("is_ai_workload") and asset.get("asset_type") in ("k8s_pod", "agentic_framework"):
                if asset.get("risk_score", 0) >= 40:
                    result.threats.append({
                        "title": f"AI workload '{asset['name']}' detected in cluster",
                        "description": (
                            f"Pod '{asset['name']}' shows AI workload signatures (image, env vars, or ports). "
                            "Verify this is authorized and properly isolated."
                        ),
                        "severity": "medium",
                        "category": "model_abuse",
                        "raw_evidence": {"asset_name": asset["name"], "metadata": meta},
                        "mitre_atlas": "AML.T0007",
                    })
        return result
