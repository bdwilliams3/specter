import httpx
import logging
from app.scanners.base import BaseScanner, ScanResult
from app.config import settings

logger = logging.getLogger(__name__)

# Known AI tool fingerprints: image substrings, env var names, port numbers
AI_IMAGE_FINGERPRINTS = [
    "ollama", "vllm", "triton", "llama", "mistral", "gemma",
    "huggingface", "transformers", "langchain", "fastmcp", "mcp-server",
    "openai", "anthropic", "litellm", "text-generation-inference",
    "crewai", "autogen", "langfuse", "mlflow",
]

AI_ENV_FINGERPRINTS = [
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY",
    "HF_TOKEN", "HUGGINGFACE_TOKEN", "AWS_BEDROCK", "AZURE_OPENAI_API_KEY",
    "LANGCHAIN_API_KEY", "LANGFUSE_SECRET_KEY", "IBM_API_KEY",
]

AI_PORT_FINGERPRINTS = [11434, 8080, 8000, 7860, 3000, 5000]  # ollama, common model servers


class KubernetesMCPScanner(BaseScanner):
    name = "k8s_mcp"
    display_name = "Kubernetes (via MCP)"

    async def _mcp_call(self, client: httpx.AsyncClient, tool: str, args: dict) -> dict:
        payload = {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": args}
        }
        resp = await client.post(settings.mcp_server_url, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise RuntimeError(data["error"])
        result = data.get("result", {})
        # FastMCP returns content as list of text blocks
        content = result.get("content", [])
        if content and isinstance(content, list):
            import json
            text = content[0].get("text", "{}")
            try:
                return json.loads(text)
            except Exception:
                return {"raw": text}
        return result

    async def _init_mcp(self, client: httpx.AsyncClient):
        payload = {
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "specter", "version": "1.0.0"}}
        }
        await client.post(settings.mcp_server_url, json=payload, timeout=10)

    def _is_ai_workload(self, pod: dict) -> bool:
        spec = pod.get("spec", {})
        for container in spec.get("containers", []):
            image = container.get("image", "").lower()
            if any(f in image for f in AI_IMAGE_FINGERPRINTS):
                return True
            for env in container.get("env", []):
                if env.get("name", "") in AI_ENV_FINGERPRINTS:
                    return True
            for port in container.get("ports", []):
                if port.get("containerPort") in AI_PORT_FINGERPRINTS:
                    return True
        return False

    async def scan(self, target: str, config: dict) -> ScanResult:
        result = ScanResult()
        namespace = target if target != "all" else "workload"

        async with httpx.AsyncClient() as client:
            try:
                await self._init_mcp(client)
            except Exception as e:
                logger.warning(f"MCP init failed: {e}")

            # Collect pods
            try:
                pods_data = await self._mcp_call(client, "list_pods", {"namespace": namespace})
                pods = pods_data if isinstance(pods_data, list) else pods_data.get("items", [])
            except Exception as e:
                logger.error(f"list_pods failed: {e}")
                pods = []

            # Collect deployments
            try:
                deps_data = await self._mcp_call(client, "list_deployments", {"namespace": namespace})
                deployments = deps_data if isinstance(deps_data, list) else deps_data.get("items", [])
            except Exception as e:
                logger.error(f"list_deployments failed: {e}")
                deployments = []

            # Collect services
            try:
                svcs_data = await self._mcp_call(client, "list_services", {"namespace": namespace})
                services = svcs_data if isinstance(svcs_data, list) else svcs_data.get("items", [])
            except Exception as e:
                logger.error(f"list_services failed: {e}")
                services = []

            # Collect network policies
            try:
                np_data = await self._mcp_call(client, "list_network_policies", {"namespace": namespace})
                net_policies = np_data if isinstance(np_data, list) else np_data.get("items", [])
            except Exception as e:
                logger.error(f"list_network_policies failed: {e}")
                net_policies = []

            # Collect events for threat detection
            try:
                events_data = await self._mcp_call(client, "get_events", {"namespace": namespace})
                events = events_data if isinstance(events_data, list) else events_data.get("items", [])
            except Exception as e:
                logger.error(f"get_events failed: {e}")
                events = []

        # Build asset records
        asset_ids = {}
        for pod in pods:
            meta = pod.get("metadata", {})
            name = meta.get("name", "unknown")
            is_ai = self._is_ai_workload(pod)
            asset = {
                "name": name,
                "asset_type": "mcp_server" if "mcp" in name.lower() else ("k8s_pod" if not is_ai else "agentic_framework"),
                "provider": "k8s",
                "namespace": meta.get("namespace", namespace),
                "cluster": "ghost-cluster",
                "metadata_": {
                    "phase": pod.get("status", {}).get("phase"),
                    "node": pod.get("spec", {}).get("nodeName"),
                    "images": [c.get("image") for c in pod.get("spec", {}).get("containers", [])],
                    "is_ai_workload": is_ai,
                },
                "risk_score": 40 if is_ai else 10,
            }
            result.assets.append(asset)
            asset_ids[name] = asset

        for dep in deployments:
            meta = dep.get("metadata", {})
            name = meta.get("name", "unknown")
            asset = {
                "name": name,
                "asset_type": "k8s_deployment",
                "provider": "k8s",
                "namespace": meta.get("namespace", namespace),
                "cluster": "ghost-cluster",
                "metadata_": {
                    "replicas": dep.get("spec", {}).get("replicas", 1),
                    "available": dep.get("status", {}).get("availableReplicas", 0),
                },
                "risk_score": 10,
            }
            result.assets.append(asset)

        for svc in services:
            meta = svc.get("metadata", {})
            spec = svc.get("spec", {})
            svc_type = spec.get("type", "ClusterIP")
            name = meta.get("name", "unknown")
            asset = {
                "name": name,
                "asset_type": "k8s_service",
                "provider": "k8s",
                "namespace": meta.get("namespace", namespace),
                "cluster": "ghost-cluster",
                "metadata_": {"type": svc_type, "ports": spec.get("ports", [])},
                "risk_score": 30 if svc_type == "NodePort" else 10,
            }
            result.assets.append(asset)

        # Vulnerability: pods without network policy coverage
        covered_namespaces = {np.get("metadata", {}).get("namespace") for np in net_policies}
        if namespace not in covered_namespaces:
            result.vulnerabilities.append({
                "title": f"No NetworkPolicy in namespace '{namespace}'",
                "description": f"Namespace '{namespace}' has no NetworkPolicy resources. AI workloads are reachable without restriction.",
                "severity": "high",
                "category": "no_network_policy",
                "remediation": "Apply a default-deny NetworkPolicy and explicitly allow only required traffic.",
                "cvss_score": 7.5,
            })

        # Vulnerability: NodePort services exposing AI workloads
        for svc in services:
            if svc.get("spec", {}).get("type") == "NodePort":
                svc_name = svc.get("metadata", {}).get("name", "unknown")
                result.vulnerabilities.append({
                    "title": f"NodePort service '{svc_name}' exposes workload externally",
                    "description": f"Service '{svc_name}' uses NodePort which may expose AI endpoints to the host network.",
                    "severity": "medium",
                    "category": "exposed_endpoint",
                    "remediation": "Use ClusterIP and expose externally via Ingress with TLS only.",
                    "cvss_score": 5.3,
                })

        # Threat: exec events into AI pods
        for event in events:
            reason = event.get("reason", "")
            msg = event.get("message", "")
            involved = event.get("involvedObject", {})
            if reason == "Started" and any(f in msg.lower() for f in ["exec", "attach"]):
                result.threats.append({
                    "title": f"Exec/attach into pod '{involved.get('name', 'unknown')}'",
                    "description": f"An exec or attach session was detected: {msg}",
                    "severity": "high",
                    "category": "unauthorized_access",
                    "raw_evidence": event,
                    "mitre_atlas": "AML.T0012",
                })

        return result
