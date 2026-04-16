"""
Processes Tetragon network events: correlate against AI asset inventory,
detect suspicious pod-to-pod connections, persist threats.
"""
import logging
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import AIAsset
from app.models.threat import ThreatEvent, ThreatSeverity, ThreatCategory
from app.services.ws_manager import ws_manager

logger = logging.getLogger(__name__)

# Ports commonly used by AI/MCP workloads
AI_PORTS = {8000, 8080, 8443, 11434, 4000, 3000, 5000}

# Namespaces that contain AI workloads — events from these always evaluated
AI_NAMESPACES = {"workload", "specter"}

# Known external AI API destinations
AI_EXTERNAL_HOSTS = {
    "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
    "api.cohere.ai", "inference.ai.azure.com",
}

# Pod name prefixes for k8s infrastructure — never signal threats
_SYSTEM_POD_PREFIXES = (
    "kube-", "coredns-", "etcd-", "kindnet-", "local-path-",
    "tetragon-", "node-debugger-",
)


def _is_external(ip: str) -> bool:
    """Returns True if IP is not a cluster-internal RFC1918 or loopback address."""
    return not (
        ip.startswith("10.") or
        ip.startswith("172.") or
        ip.startswith("192.168.") or
        ip.startswith("127.") or
        ip == "::1"
    )


def _is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip == "::1"


def _is_system_pod(pod: str) -> bool:
    return any(pod.startswith(p) for p in _SYSTEM_POD_PREFIXES)


async def process_network_events(events: list[dict], db: AsyncSession) -> int:
    if not events:
        return 0

    result = await db.execute(select(AIAsset.name, AIAsset.id, AIAsset.asset_type))
    rows = result.all()
    ai_pod_names = {r.name for r in rows}
    name_to_id = {r.name: r.id for r in rows}

    new_threats = 0
    for event in events:
        threat = _evaluate_network_event(event, ai_pod_names)
        if not threat:
            continue

        pod_name = event.get("pod", "")
        asset_id = name_to_id.get(pod_name)

        try:
            threat_name = threat["threat_name"]
            t = ThreatEvent(
                asset_id=asset_id,
                threat_name=threat_name,
                title=threat_name,
                description=threat["description"],
                severity=ThreatSeverity(threat["severity"]),
                category=ThreatCategory(threat["category"]),
                principal_role=threat.get("principal_role"),
                principal_subject=threat.get("principal_subject"),
                method=threat.get("method"),
                resource=threat.get("resource"),
                namespace=threat.get("namespace"),
                source_ips=threat.get("source_ips"),
                raw_evidence=threat.get("raw_evidence", {}),
                mitre_atlas=threat.get("mitre_atlas"),
                detected_at=datetime.utcnow(),
            )
            db.add(t)
            await db.flush()
            new_threats += 1

            await ws_manager.broadcast({
                "type": "threat",
                "id": t.id,
                "title": t.title,
                "severity": t.severity.value,
                "category": t.category.value,
                "detected_at": t.detected_at.isoformat(),
            })

        except Exception as e:
            logger.warning("Failed to persist network threat: %s", e)

    if new_threats:
        await db.commit()
        logger.info("Persisted %d threats from %d network events", new_threats, len(events))

    return new_threats


def _evaluate_network_event(event: dict, ai_pod_names: set[str]) -> dict | None:
    pod      = event.get("pod", "")
    ns       = event.get("namespace", "")
    src_ip   = event.get("src_ip", "")
    dst_ip   = event.get("dst_ip", "")
    dst_port = event.get("dst_port", 0)
    binary   = event.get("binary", "")
    ts       = event.get("timestamp", "")

    # Drop loopback self-connections (health checks, local IPC) and k8s infra pods
    if _is_loopback(dst_ip) or _is_system_pod(pod):
        return None

    # Source must be an AI workload: either a known scanned asset OR in an AI namespace.
    # Namespace check ensures detection works before any asset scan has run.
    is_ai_source = pod in ai_pod_names or ns in AI_NAMESPACES
    if not is_ai_source:
        return None

    evidence = {
        "pod": pod, "namespace": ns,
        "src_ip": src_ip, "dst_ip": dst_ip,
        "dst_port": dst_port, "binary": binary,
        "cluster": event.get("cluster"), "timestamp": ts,
    }

    # Rule: AI pod → AI service port (agent lateral movement / unauthorized MCP call)
    # High when source is a known asset (confirmed AI workload), medium when namespace-inferred.
    if dst_port in AI_PORTS:
        sev = "high" if pod in ai_pod_names else "medium"
        return {
            "threat_name": "AI Agent Lateral Movement via Internal API",
            "description": (
                f"Pod '{pod}' (ns: {ns}) established TCP to {dst_ip}:{dst_port}. "
                f"Port {dst_port} is associated with AI/MCP services. "
                "Unauthorized agent-to-tool calls may indicate a compromised AI agent performing lateral movement."
            ),
            "severity": sev,
            "category": "anomalous_api_usage",
            "principal_role": "AIWorkload",
            "principal_subject": pod,
            "method": "tcp_connect",
            "resource": f"port/{dst_port}",
            "namespace": ns,
            "source_ips": [src_ip] if src_ip else [],
            "raw_evidence": evidence,
            "mitre_atlas": "AML.T0011",
        }

    # Rule: AI pod → external internet (unsanctioned LLM call / data exfiltration)
    if _is_external(dst_ip) and dst_port in (443, 80):
        return {
            "threat_name": "Unauthorized AI Workload External Egress",
            "description": (
                f"Pod '{pod}' (ns: {ns}) connected to external IP {dst_ip}:{dst_port}. "
                "AI workloads calling external endpoints may indicate unsanctioned LLM usage or data exfiltration."
            ),
            "severity": "high",
            "category": "data_exfiltration",
            "principal_role": "AIWorkload",
            "principal_subject": pod,
            "method": "tcp_connect",
            "resource": f"{dst_ip}:{dst_port}",
            "namespace": ns,
            "source_ips": [src_ip] if src_ip else [],
            "raw_evidence": evidence,
            "mitre_atlas": "AML.T0037",
        }

    return None
