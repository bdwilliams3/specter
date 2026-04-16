import logging
from app.detectors.base import BaseDetector
from app.scanners.base import ScanResult

logger = logging.getLogger(__name__)


class VulnDetector(BaseDetector):
    def analyze(self, result: ScanResult, raw_context: dict) -> ScanResult:
        for asset in result.assets:
            meta = asset.get("metadata_", {})
            # Privileged container check (if surfaced in metadata)
            if meta.get("privileged"):
                result.vulnerabilities.append({
                    "title": f"Privileged container in '{asset['name']}'",
                    "description": "A container is running in privileged mode, granting full host access.",
                    "severity": "critical",
                    "category": "insecure_config",
                    "remediation": "Remove the privileged: true flag and use specific capabilities instead.",
                    "cvss_score": 9.8,
                })
            # No resource limits
            if meta.get("is_ai_workload") and not meta.get("resource_limits"):
                result.vulnerabilities.append({
                    "title": f"No resource limits on AI workload '{asset['name']}'",
                    "description": "AI workloads without resource limits can exhaust cluster resources (DoS risk).",
                    "severity": "medium",
                    "category": "insecure_config",
                    "remediation": "Set CPU and memory limits on all AI containers.",
                    "cvss_score": 5.0,
                })
        return result
