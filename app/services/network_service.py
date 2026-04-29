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
from app.services.asset_scoring import AI_PROVIDER_HOSTS, add_runtime_signal
from app.services.ws_manager import ws_manager

logger = logging.getLogger(__name__)

# Ports commonly used by AI/MCP workloads
AI_PORTS = {8000, 8080, 8443, 11434, 4000, 3000, 5000}

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

# Binaries expected to initiate network calls from AI workloads. Anything else
# egressing from an AI pod is worth a second look — a shell, curl, wget, nc,
# nmap, python-oneliner, or custom binary on the wire is the classic exfil
# fingerprint. Keep this tight; broadening it to every interpreter defeats
# the rule.
_EXPECTED_AI_BINARIES = {
    "python", "python3", "node", "java", "uvicorn", "gunicorn",
    "ollama", "vllm", "triton", "tritonserver", "text-generation-server",
    "ray", "litellm",
}


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

    result = await db.execute(select(AIAsset))
    assets = result.scalars().all()
    ai_pod_names = {asset.name for asset in assets}
    name_to_asset = {(asset.name, asset.namespace): asset for asset in assets}
    name_to_id = {asset.name: asset.id for asset in assets}

    new_threats = 0
    new_signals = 0
    for event in events:
        pod_name = event.get("pod", "")
        namespace = event.get("namespace")
        asset = name_to_asset.get((pod_name, namespace))
        signal = _runtime_ai_signal(event)
        if asset and signal:
            await add_runtime_signal(db, asset, signal)
            new_signals += 1

        threat = _evaluate_network_event(event, ai_pod_names)
        if not threat:
            continue

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

    if new_threats or new_signals:
        await db.commit()
        logger.info(
            "Persisted %d threats and %d AI signals from %d network events",
            new_threats, new_signals, len(events)
        )

    return new_threats


def _runtime_ai_signal(event: dict) -> dict | None:
    event_type = event.get("type") or event.get("event_type") or event.get("kind")
    host = (
        event.get("dns_query")
        or event.get("query")
        or event.get("sni")
        or event.get("tls_sni")
        or event.get("server_name")
        or event.get("host")
        or ""
    ).lower().rstrip(".")
    if not host or host not in AI_PROVIDER_HOSTS:
        return None
    signal_type = "ai_provider_sni" if event_type in {"tls_sni", "sni", "tls"} else "ai_provider_dns"
    return {
        "signal_type": signal_type,
        "source": "tetragon",
        "value": host,
        "weight": 5.0,
    }


def _evaluate_network_event(event: dict, ai_pod_names: set[str]) -> dict | None:
    pod      = event.get("pod", "")
    ns       = event.get("namespace", "")
    src_ip   = event.get("src_ip", "")
    dst_ip   = event.get("dst_ip", "")
    dst_port = event.get("dst_port", 0)
    binary   = (event.get("binary") or "").split("/")[-1]  # strip path
    ts       = event.get("timestamp", "")

    # Drop loopback self-connections (health checks, local IPC) and k8s infra pods
    if _is_loopback(dst_ip) or _is_system_pod(pod):
        return None

    evidence = {
        "pod": pod, "namespace": ns,
        "src_ip": src_ip, "dst_ip": dst_ip,
        "dst_port": dst_port, "binary": binary,
        "cluster": event.get("cluster"), "timestamp": ts,
    }

    src_is_ai = pod in ai_pod_names

    # ── Rule: non-AI pod probing an AI service port (T0040 — reconnaissance) ──
    # Catches the reverse direction: a pod that is NOT in the AI inventory
    # reaching toward an AI/MCP port internally. Classic lateral-recon signal
    # for anything looking to map AI surface area (e.g., a compromised ops
    # workload scanning for Ollama/VLLM endpoints).
    if not src_is_ai and dst_port in AI_PORTS and not _is_external(dst_ip):
        return {
            "threat_name": "Probing of AI Service Port by Non-AI Workload",
            "description": (
                f"Non-inventoried pod '{pod}' (ns: {ns}) connected to internal "
                f"{dst_ip}:{dst_port}. Port {dst_port} is associated with AI/MCP "
                "services — reconnaissance against the AI surface area."
            ),
            "severity": "medium",
            "category": "anomalous_api_usage",
            "principal_role": "NonAIWorkload",
            "principal_subject": pod,
            "method": "tcp_connect",
            "resource": f"port/{dst_port}",
            "namespace": ns,
            "source_ips": [src_ip] if src_ip else [],
            "raw_evidence": evidence,
            "mitre_atlas": "AML.T0040",
        }

    # Everything below requires the source to be an inventoried AI workload.
    if not src_is_ai:
        return None

    # ── Rule: AI pod → AI service port (lateral movement / unauthorized MCP) ──
    if dst_port in AI_PORTS:
        return {
            "threat_name": "AI Agent Lateral Movement via Internal API",
            "description": (
                f"AI workload '{pod}' (ns: {ns}) established TCP to {dst_ip}:{dst_port}. "
                f"Port {dst_port} is associated with AI/MCP services. "
                "Unauthorized agent-to-tool calls may indicate a compromised AI agent "
                "performing lateral movement."
            ),
            "severity": "high",
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

    # ── Rule: AI pod outbound by unexpected binary (T0025 — exfiltration) ─────
    # An AI pod should egress under python/node/uvicorn/etc. Anything else —
    # a shell, curl, nc, nmap, wget, or a custom binary — is the classic
    # post-exploitation exfil fingerprint. External egress only; internal
    # traffic from a tool-binary can be legitimate (kubectl probes etc.).
    if binary and _is_external(dst_ip) and binary not in _EXPECTED_AI_BINARIES:
        return {
            "threat_name": "AI Pod Egress by Unexpected Binary",
            "description": (
                f"AI workload '{pod}' (ns: {ns}) egressed to {dst_ip}:{dst_port} "
                f"under binary '{binary}'. AI runtimes are expected to call out under "
                "their interpreter — a shell, curl, wget or unknown binary is the "
                "signature of a post-exploitation exfiltration path."
            ),
            "severity": "medium",
            "category": "data_exfiltration",
            "principal_role": "AIWorkload",
            "principal_subject": pod,
            "method": "tcp_connect",
            "resource": f"{dst_ip}:{dst_port}",
            "namespace": ns,
            "source_ips": [src_ip] if src_ip else [],
            "raw_evidence": evidence,
            "mitre_atlas": "AML.T0025",
        }

    # ── Rule: AI pod → external internet (unsanctioned LLM / exfiltration) ────
    if _is_external(dst_ip) and dst_port in (443, 80):
        return {
            "threat_name": "Unauthorized AI Workload External Egress",
            "description": (
                f"Pod '{pod}' (ns: {ns}) connected to external IP {dst_ip}:{dst_port}. "
                "AI workloads calling external endpoints may indicate unsanctioned "
                "LLM usage or data exfiltration."
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
