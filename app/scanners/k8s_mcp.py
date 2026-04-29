import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from app.scanners.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)

# Env vars that indicate a workload is CONSUMING an LLM API (agent or app)
LLM_CONSUMER_ENVS = {
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY",
    "COHERE_API_KEY", "HUGGINGFACE_TOKEN", "HF_TOKEN", "REPLICATE_API_TOKEN",
    "MISTRAL_API_KEY", "GROQ_API_KEY", "TOGETHER_API_KEY", "LANGCHAIN_API_KEY",
    "AZURE_OPENAI_API_KEY", "IBM_API_KEY", "ALIBABA_AI_KEY",
    # Google ADK
    "GOOGLE_GENAI_API_KEY", "GOOGLE_CLOUD_PROJECT",
}

# Env vars that indicate a workload has TOOL/ORCHESTRATION access (agent signal)
AGENT_TOOL_ENVS = {
    "MCP_SERVER_URL", "MCP_HOST", "MCP_ENDPOINT",
    "LANGCHAIN_API_KEY", "LANGFUSE_SECRET_KEY",
    "CREW_AI", "AUTOGEN_", "ADK_AGENT",
    "TOOL_SERVER_URL", "AGENT_TOOLS",
}

# Env vars that indicate a workload is SERVING a model
MODEL_SERVER_ENVS = {
    "OLLAMA_HOST", "OLLAMA_MODELS",
    "MODEL_PATH", "HF_MODEL_ID",
    "VLLM_", "TRITON_",
}

# All AI env vars combined for initial detection
AI_ENV_NAMES = LLM_CONSUMER_ENVS | AGENT_TOOL_ENVS | MODEL_SERVER_ENVS

# Port numbers commonly used by AI/MCP workloads
AI_PORTS = {
    8000: "mcp/fastapi",
    11434: "ollama",
    7860: "gradio",
    8501: "streamlit",
    8888: "jupyter",
}

WEAK_AI_TERMS = {
    "ai", "llm", "model", "openai", "anthropic", "gemini", "ollama",
    "vllm", "langchain", "autogen", "crewai", "mcp", "huggingface",
}

AI_IMAGE_TERMS = {
    "ollama", "vllm", "triton", "text-generation-inference", "tgi",
    "langchain", "openai", "anthropic", "mcp", "huggingface",
}

GPU_RESOURCE_KEYS = {
    "nvidia.com/gpu", "amd.com/gpu", "habana.ai/gaudi", "google.com/tpu",
}

AI_DEVICE_PATH_TERMS = {
    "/dev/nvidia", "/dev/dri", "/dev/kfd", "/dev/infiniband",
}

# Ports that strongly indicate serving (not consuming)
SERVER_PORTS = {8000, 11434, 7860, 8501}


def _load_k8s():
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


def _classify_asset(signals: dict) -> str:
    """
    Classify the asset type based on observed signals.

    Logic:
    - Consumes LLM API AND has tool/orchestration env  → agent (agentic_framework)
    - Consumes LLM API, no serving port                → agent (agentic_framework)
    - Serves on MCP/FastAPI port (8000), no LLM consumer env → mcp_server
    - Serves on Ollama port (11434)                    → model_server
    - Serves on other model port                       → model_server
    - Has LLM consumer env + serves on AI port         → could be agent with embedded server → agentic_framework
    """
    env_vars = set(signals["ai_env_vars"])
    port_numbers = {p["port"] for p in signals["ai_ports"]}

    has_llm_consumer = bool(env_vars & LLM_CONSUMER_ENVS)
    has_tool_env = bool(any(e.startswith(prefix) for e in env_vars for prefix in AGENT_TOOL_ENVS))
    serves_mcp = 8000 in port_numbers
    serves_ollama = 11434 in port_numbers
    serves_model = bool(port_numbers & {5000})

    if serves_ollama or (serves_model and not has_llm_consumer):
        return "model_server"
    if serves_mcp and not has_llm_consumer:
        return "mcp_server"
    if has_llm_consumer or has_tool_env:
        return "agentic_framework"
    # Serving on an AI port with no other signals — treat as model server
    if port_numbers & SERVER_PORTS:
        return "model_server"
    return "agentic_framework"


def _extract_container_signals(containers: list) -> dict:
    """Extract AI signals and security posture from container specs."""
    ai_env_found = []
    ai_ports_found = []
    images = []
    has_resource_limits = True
    has_readonly_root = True
    runs_as_nonroot = True
    privileged = False
    llm_envs_exposed = []
    gpu_resource_limits = []
    device_mounts = []

    for container in containers:
        images.append(container.image or "")

        # Env var names only — never log values
        for env in (container.env or []):
            if env.name in AI_ENV_NAMES or any(env.name.startswith(p) for p in AGENT_TOOL_ENVS):
                ai_env_found.append(env.name)
            if env.name in LLM_CONSUMER_ENVS:
                llm_envs_exposed.append(env.name)

        # Port declarations
        for port in (container.ports or []):
            if port.container_port in AI_PORTS:
                ai_ports_found.append({
                    "port": port.container_port,
                    "protocol": port.protocol or "TCP",
                    "hint": AI_PORTS[port.container_port],
                })

        # Resource limits
        resources = container.resources
        if not resources or not resources.limits:
            has_resource_limits = False
        else:
            for key, value in (resources.limits or {}).items():
                if str(key) in GPU_RESOURCE_KEYS:
                    gpu_resource_limits.append({"resource": str(key), "value": str(value)})

        for mount in (container.volume_mounts or []):
            mount_path = mount.mount_path or ""
            if any(term in mount_path for term in AI_DEVICE_PATH_TERMS):
                device_mounts.append(mount_path)

        # Security context
        sc = container.security_context
        if not sc:
            has_readonly_root = False
            runs_as_nonroot = False
        else:
            if not sc.read_only_root_filesystem:
                has_readonly_root = False
            if not sc.run_as_non_root:
                runs_as_nonroot = False
            if sc.privileged:
                privileged = True

    return {
        "images": images,
        "ai_env_vars": ai_env_found,
        "ai_ports": ai_ports_found,
        "llm_envs_exposed": llm_envs_exposed,
        "has_resource_limits": has_resource_limits,
        "gpu_resource_limits": gpu_resource_limits,
        "device_mounts": device_mounts,
        "has_readonly_root": has_readonly_root,
        "runs_as_nonroot": runs_as_nonroot,
        "privileged": privileged,
    }


def _metadata_dict(meta) -> dict:
    labels = meta.labels or {}
    annotations = meta.annotations or {}
    return {
        "name": meta.name or "",
        "labels": labels,
        "annotations": annotations,
    }


def _has_weak_term(value: str) -> bool:
    lowered = value.lower()
    return any(term in lowered for term in WEAK_AI_TERMS)


def _build_ai_signals(meta, signals: dict, source: str) -> list[dict]:
    meta_dict = _metadata_dict(meta)
    out: list[dict] = []

    for env_name in sorted(set(signals["ai_env_vars"])):
        if env_name in LLM_CONSUMER_ENVS:
            signal_type, weight = "llm_api_env", 4.0
        elif env_name in MODEL_SERVER_ENVS or any(env_name.startswith(p) for p in MODEL_SERVER_ENVS):
            signal_type, weight = "model_server_env", 3.0
        else:
            signal_type, weight = "agent_tool_env", 3.0
        out.append({"signal_type": signal_type, "source": source, "value": env_name, "weight": weight})

    for port in signals["ai_ports"]:
        out.append({
            "signal_type": "declared_ai_port",
            "source": source,
            "value": str(port["port"]),
            "weight": 2.0,
        })

    for image in signals["images"]:
        lowered = image.lower()
        if any(term in lowered for term in AI_IMAGE_TERMS):
            out.append({"signal_type": "weak_image_match", "source": source, "value": image, "weight": 1.0})

    if _has_weak_term(meta_dict["name"]):
        out.append({"signal_type": "weak_name_match", "source": source, "value": meta_dict["name"], "weight": 1.0})

    for key, value in meta_dict["labels"].items():
        rendered = f"{key}={value}"
        if _has_weak_term(rendered):
            out.append({"signal_type": "weak_label_match", "source": source, "value": rendered, "weight": 1.0})

    for key, value in meta_dict["annotations"].items():
        rendered = f"{key}={value}"
        if _has_weak_term(rendered):
            out.append({"signal_type": "weak_annotation_match", "source": source, "value": rendered, "weight": 1.0})

    for gpu in signals["gpu_resource_limits"]:
        out.append({
            "signal_type": "gpu_resource_limit",
            "source": source,
            "value": f"{gpu['resource']}={gpu['value']}",
            "weight": 3.0,
        })

    for mount_path in signals["device_mounts"]:
        out.append({"signal_type": "device_mount", "source": source, "value": mount_path, "weight": 3.0})

    return out


class KubernetesMCPScanner(BaseScanner):
    name = "k8s_mcp"
    display_name = "Kubernetes (All Namespaces)"

    async def scan(self, target: str, config_dict: dict) -> ScanResult:
        result = ScanResult()

        try:
            _load_k8s()
        except Exception as e:
            logger.error(f"Failed to load k8s config: {e}")
            return result

        v1 = client.CoreV1Api()
        apps_v1 = client.AppsV1Api()
        net_v1 = client.NetworkingV1Api()

        # --- Collect all pods across all namespaces ---
        try:
            pods = v1.list_pod_for_all_namespaces(watch=False)
        except ApiException as e:
            logger.error(f"list_pod_for_all_namespaces failed: {e}")
            return result

        # Track AI pod names per namespace for service/vuln correlation
        ai_pod_namespaces: set[str] = set()

        # Cache SA rules to avoid repeated API calls: (namespace, sa_name) -> list[rule_dict]
        rbac_v1 = client.RbacAuthorizationV1Api()
        _sa_verbs_cache: dict[tuple, list] = {}

        def _get_sa_verbs(namespace: str, sa_name: str) -> list[dict]:
            key = (namespace, sa_name)
            if key in _sa_verbs_cache:
                return _sa_verbs_cache[key]
            rules = []
            try:
                # Check RoleBindings in namespace
                rbs = rbac_v1.list_namespaced_role_binding(namespace, watch=False)
                for rb in rbs.items:
                    for subj in rb.subjects or []:
                        if subj.kind == "ServiceAccount" and subj.name == sa_name:
                            try:
                                role = rbac_v1.read_namespaced_role(rb.role_ref.name, namespace)
                                for rule in role.rules or []:
                                    rules.append({
                                        "resources": rule.resources or [],
                                        "verbs": rule.verbs or [],
                                    })
                            except Exception:
                                pass
                # Check ClusterRoleBindings
                crbs = rbac_v1.list_cluster_role_binding(watch=False)
                for crb in crbs.items:
                    for subj in crb.subjects or []:
                        if subj.kind == "ServiceAccount" and subj.name == sa_name and subj.namespace == namespace:
                            try:
                                cr = rbac_v1.read_cluster_role(crb.role_ref.name)
                                for rule in cr.rules or []:
                                    rules.append({
                                        "resources": rule.resources or [],
                                        "verbs": rule.verbs or [],
                                    })
                            except Exception:
                                pass
            except Exception as e:
                logger.warning(f"Could not fetch RBAC for {sa_name}: {e}")
            _sa_verbs_cache[key] = rules
            return rules

        for pod in pods.items:
            meta = pod.metadata
            spec = pod.spec
            status = pod.status

            signals = _extract_container_signals(spec.containers or [])
            ai_signals = _build_ai_signals(meta, signals, "k8s_pod")
            is_ai = bool(signals["ai_env_vars"] or signals["ai_ports"] or ai_signals)

            # Only inventory AI workloads
            if not is_ai:
                continue

            ai_pod_namespaces.add(meta.namespace)
            asset_type = _classify_asset(signals)

            sa_name = spec.service_account_name or "default"
            sa_verbs = _get_sa_verbs(meta.namespace, sa_name)
            automount = spec.automount_service_account_token
            # None means not explicitly set — defaults to True in k8s
            automount_enabled = automount is None or automount is True

            result.assets.append({
                "name": meta.name,
                "asset_type": asset_type,
                "provider": "k8s",
                "namespace": meta.namespace,
                "cluster": target or "in-cluster",
                "metadata_": {
                    "phase": status.phase if status else None,
                    "node": spec.node_name,
                    "images": signals["images"],
                    "ai_env_vars": signals["ai_env_vars"],
                    "ai_ports": signals["ai_ports"],
                    "ai_signals": ai_signals,
                    "llm_envs_exposed": signals["llm_envs_exposed"],
                    "has_resource_limits": signals["has_resource_limits"],
                    "gpu_resource_limits": signals["gpu_resource_limits"],
                    "device_mounts": signals["device_mounts"],
                    "has_readonly_root": signals["has_readonly_root"],
                    "runs_as_nonroot": signals["runs_as_nonroot"],
                    "privileged": signals["privileged"],
                    "service_account": sa_name,
                    "sa_verbs": sa_verbs,
                    "automount_sa_token": automount_enabled,
                },
                "ai_signals": ai_signals,
                "risk_score": 60,
            })

        # --- Collect all services ---
        try:
            services = v1.list_service_for_all_namespaces(watch=False)
        except ApiException as e:
            logger.error(f"list_service_for_all_namespaces failed: {e}")
            services = type("obj", (object,), {"items": []})

        for svc in services.items:
            meta = svc.metadata
            spec = svc.spec
            svc_type = spec.type or "ClusterIP"
            svc_ports = spec.ports or []
            port_numbers = {p.port for p in svc_ports}
            ports = [{"port": p.port, "target_port": str(p.target_port), "protocol": p.protocol}
                     for p in svc_ports]

            # Only inventory services in AI namespaces or serving AI ports
            serves_ai_port = bool(port_numbers & set(AI_PORTS.keys()))
            in_ai_namespace = meta.namespace in ai_pod_namespaces
            if not serves_ai_port and not in_ai_namespace:
                continue

            result.assets.append({
                "name": meta.name,
                "asset_type": "k8s_service",
                "provider": "k8s",
                "namespace": meta.namespace,
                "cluster": target or "in-cluster",
                "metadata_": {"type": svc_type, "ports": ports},
                "ai_signals": [
                    {
                        "signal_type": "declared_ai_port",
                        "source": "k8s_service",
                        "value": str(port),
                        "weight": 2.0,
                    }
                    for port in sorted(port_numbers & set(AI_PORTS.keys()))
                ],
                "risk_score": 30 if svc_type == "NodePort" else 10,
            })

        # --- Collect all deployments ---
        try:
            deployments = apps_v1.list_deployment_for_all_namespaces(watch=False)
        except ApiException as e:
            logger.error(f"list_deployment_for_all_namespaces failed: {e}")
            deployments = type("obj", (object,), {"items": []})

        for dep in deployments.items:
            meta = dep.metadata
            spec = dep.spec
            status = dep.status

            # Only inventory deployments whose pod template has AI signals
            pod_template_containers = spec.template.spec.containers if spec.template and spec.template.spec else []
            signals = _extract_container_signals(pod_template_containers)
            ai_signals = _build_ai_signals(meta, signals, "k8s_deployment")
            if not signals["ai_env_vars"] and not signals["ai_ports"] and not ai_signals:
                continue

            result.assets.append({
                "name": meta.name,
                "asset_type": "k8s_deployment",
                "provider": "k8s",
                "namespace": meta.namespace,
                "cluster": target or "in-cluster",
                "metadata_": {
                    "replicas": spec.replicas,
                    "ready": status.ready_replicas if status else 0,
                    "ai_ports": signals["ai_ports"],
                    "ai_env_vars": signals["ai_env_vars"],
                    "ai_signals": ai_signals,
                    "gpu_resource_limits": signals["gpu_resource_limits"],
                    "device_mounts": signals["device_mounts"],
                },
                "ai_signals": ai_signals,
                "risk_score": 60,
            })

        # --- Vulnerabilities scoped to AI namespaces only ---
        try:
            net_policies = net_v1.list_network_policy_for_all_namespaces(watch=False)
            covered = {p.metadata.namespace for p in net_policies.items}
        except ApiException:
            covered = set()

        # Missing NetworkPolicy — only flag namespaces that contain AI workloads
        for ns in ai_pod_namespaces:
            if ns not in covered:
                result.vulnerabilities.append({
                    "asset_name": f"namespace:{ns}",
                    "title": f"AI workloads in '{ns}' have no network isolation",
                    "description": (
                        f"Namespace '{ns}' contains AI workloads but has no NetworkPolicy. "
                        "Any pod in the cluster can reach these AI services, enabling data exfiltration or prompt injection via lateral movement."
                    ),
                    "severity": "high",
                    "category": "no_network_policy",
                    "remediation": "Apply a default-deny NetworkPolicy for this namespace and explicitly allow only required ingress/egress.",
                    "cvss_score": 7.5,
                })

        # NodePort on an AI service — unauthenticated external exposure
        for svc in services.items:
            if svc.spec.type == "NodePort" and svc.metadata.namespace in ai_pod_namespaces:
                result.vulnerabilities.append({
                    "asset_name": svc.metadata.name,
                    "title": f"AI service '{svc.metadata.name}' exposed via NodePort without authentication",
                    "description": (
                        f"Service '{svc.metadata.name}' in '{svc.metadata.namespace}' uses NodePort, "
                        "making the AI endpoint reachable on every cluster node without requiring authentication. "
                        "This allows unauthenticated access to the AI workload from the host network."
                    ),
                    "severity": "high",
                    "category": "exposed_endpoint",
                    "remediation": "Replace NodePort with ClusterIP. Expose externally only via an authenticated Ingress with TLS.",
                    "cvss_score": 8.2,
                })

        logger.info(
            f"k8s scan complete: {len(result.assets)} AI assets, "
            f"{len(result.vulnerabilities)} AI security findings across namespaces: {sorted(ai_pod_namespaces)}"
        )
        return result
