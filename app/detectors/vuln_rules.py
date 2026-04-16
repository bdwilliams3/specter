import logging
from app.detectors.base import BaseDetector
from app.scanners.base import ScanResult

logger = logging.getLogger(__name__)

# Verbs on sensitive resources that indicate over-permissioned SA for an AI workload
DANGEROUS_VERBS = {"create", "delete", "patch", "update"}
SENSITIVE_RESOURCES = {"pods/exec", "pods", "secrets", "clusterroles", "clusterrolebindings"}


def _sa_has_dangerous_perms(sa_verbs: list[dict]) -> list[str]:
    """Return list of dangerous resource+verb combos found in SA rules."""
    found = []
    for rule in sa_verbs:
        resources = set(rule.get("resources", []))
        verbs = set(rule.get("verbs", []))
        dangerous = resources & SENSITIVE_RESOURCES
        if dangerous and (verbs & DANGEROUS_VERBS or "*" in verbs):
            for r in dangerous:
                for v in (verbs & DANGEROUS_VERBS) or {"*"}:
                    found.append(f"{v} {r}")
    return found


class VulnDetector(BaseDetector):
    def analyze(self, result: ScanResult, raw_context: dict) -> ScanResult:
        # Track service accounts seen across AI workloads to detect sharing
        sa_to_assets: dict[str, list[str]] = {}

        for asset in result.assets:
            meta = asset.get("metadata_", {})
            name = asset.get("name", "")
            asset_type = asset.get("asset_type", "")

            # Only check pod-level assets (not services or deployments)
            if asset_type not in ("mcp_server", "agentic_framework", "model_server"):
                continue

            sa = meta.get("service_account", "")
            if sa:
                sa_to_assets.setdefault(sa, []).append(name)

            # --- Privileged container ---
            if meta.get("privileged"):
                result.vulnerabilities.append({
                    "asset_name": name,
                    "title": f"AI workload '{name}' running in privileged mode",
                    "description": "A privileged container has full access to the host. An LLM-driven workload in privileged mode can be exploited via prompt injection to escape the container.",
                    "severity": "critical",
                    "category": "insecure_config",
                    "remediation": "Remove privileged: true. Drop all capabilities and add only those required.",
                    "cvss_score": 9.8,
                })

            # --- No resource limits ---
            if not meta.get("has_resource_limits"):
                result.vulnerabilities.append({
                    "asset_name": name,
                    "title": f"AI workload '{name}' has no resource limits",
                    "description": "AI workloads without CPU/memory limits can be prompted to run expensive inference loops, exhausting cluster resources and causing denial of service.",
                    "severity": "medium",
                    "category": "insecure_config",
                    "remediation": "Set CPU and memory requests and limits on all AI containers.",
                    "cvss_score": 5.0,
                })

            # --- No read-only root filesystem ---
            if not meta.get("has_readonly_root"):
                result.vulnerabilities.append({
                    "asset_name": name,
                    "title": f"AI workload '{name}' has a writable root filesystem",
                    "description": "A writable root filesystem allows an attacker or a compromised LLM agent to write malicious files, install tools, or persist backdoors inside the container.",
                    "severity": "medium",
                    "category": "insecure_config",
                    "remediation": "Set securityContext.readOnlyRootFilesystem: true. Mount writable volumes only where explicitly needed.",
                    "cvss_score": 5.5,
                })

            # --- Not running as non-root ---
            if not meta.get("runs_as_nonroot"):
                result.vulnerabilities.append({
                    "asset_name": name,
                    "title": f"AI workload '{name}' may run as root",
                    "description": "Running as root inside the container increases the blast radius of a container escape. An LLM agent compromised via prompt injection could leverage root access for further exploitation.",
                    "severity": "medium",
                    "category": "insecure_config",
                    "remediation": "Set securityContext.runAsNonRoot: true and specify a non-zero runAsUser.",
                    "cvss_score": 5.3,
                })

            # --- Automount service account token ---
            if meta.get("automount_sa_token"):
                result.vulnerabilities.append({
                    "asset_name": name,
                    "title": f"AI workload '{name}' auto-mounts Kubernetes API token",
                    "description": "The Kubernetes service account token is automatically mounted into this AI workload. A prompt injection attack could instruct the agent to read and exfiltrate this token, granting the attacker cluster API access.",
                    "severity": "high",
                    "category": "insecure_config",
                    "remediation": "Set automountServiceAccountToken: false in the pod spec unless the workload explicitly needs cluster API access.",
                    "cvss_score": 7.5,
                })

            # --- Over-permissioned service account ---
            sa_verbs = meta.get("sa_verbs", [])
            dangerous = _sa_has_dangerous_perms(sa_verbs)
            if dangerous:
                result.vulnerabilities.append({
                    "asset_name": name,
                    "title": f"AI workload '{name}' has over-permissioned service account '{sa}'",
                    "description": (
                        f"The service account '{sa}' grants dangerous permissions: {', '.join(dangerous[:5])}. "
                        "An LLM agent with these permissions can be manipulated via prompt injection to execute arbitrary commands in pods, delete workloads, or read secrets."
                    ),
                    "severity": "critical",
                    "category": "over_permissioned",
                    "remediation": "Apply least privilege. Create a dedicated service account for this workload with only the minimum permissions required. Remove exec, delete, and write permissions unless explicitly necessary.",
                    "cvss_score": 9.1,
                })

            # --- LLM API key exposed via environment variable ---
            llm_envs = meta.get("llm_envs_exposed", [])
            if llm_envs:
                result.vulnerabilities.append({
                    "asset_name": name,
                    "title": f"AI workload '{name}' exposes LLM API credentials via environment variables",
                    "description": (
                        f"LLM API keys ({', '.join(llm_envs)}) are injected as environment variables. "
                        "Environment variables are visible in kubectl describe output, process listings, and crash dumps, increasing the risk of credential exposure."
                    ),
                    "severity": "medium",
                    "category": "insecure_config",
                    "remediation": "Mount credentials from a Secret as a file at a restricted path rather than as environment variables. Restrict access to the Secret with RBAC.",
                    "cvss_score": 6.5,
                })

            # --- MCP server specific: unauthenticated tool surface ---
            if asset_type == "mcp_server":
                result.vulnerabilities.append({
                    "asset_name": name,
                    "title": f"MCP server '{name}' exposes tool execution without authentication",
                    "description": "The MCP server accepts tool calls (including write operations like exec and delete) from any caller without authentication. Any workload in the cluster or on the host network can invoke privileged tools.",
                    "severity": "critical",
                    "category": "missing_auth",
                    "remediation": "Implement authentication on the MCP endpoint (mutual TLS or token-based). Restrict network access to known clients via NetworkPolicy.",
                    "cvss_score": 9.3,
                })

        # --- Shared service account across multiple AI workloads ---
        for sa, assets in sa_to_assets.items():
            if len(assets) > 1 and sa != "default":
                result.vulnerabilities.append({
                    "asset_name": sa,
                    "title": f"Service account '{sa}' shared across multiple AI workloads",
                    "description": (
                        f"Service account '{sa}' is used by: {', '.join(assets)}. "
                        "Sharing a service account violates least privilege — compromising any one workload grants the attacker the permissions of all others sharing the account."
                    ),
                    "severity": "high",
                    "category": "over_permissioned",
                    "remediation": "Create a dedicated service account for each AI workload with only the permissions it requires.",
                    "cvss_score": 8.0,
                })

        return result
