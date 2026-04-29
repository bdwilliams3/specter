"""
Audit-event-based threat detection rules.

Every rule gates on `ai_scope` — a set of targets derived from the `ai_assets`
inventory. If an audit event's target isn't in scope, no threat fires.

This is what makes Specter an AISPM rather than a KSPM:
  - `kubectl exec` into a random ops pod is not a threat
  - `kubectl exec` into an inventoried agent/mcp-server/model-server is
  - Installing metrics-server creates RBAC mutations that don't touch AI SAs
  - Binding an AI ServiceAccount to a ClusterRole does

The inventory ships with Specter's own discovery scanner (app/scanners/k8s_mcp.py),
which classifies workloads by observed signals (LLM env vars, AI ports, images).
No hardcoded namespaces.

Each rule is a function `(ctx, scope) -> dict | None`. `evaluate` walks the
registered rules and returns the first hit. Only ResponseComplete events with
2xx/3xx statuses reach the rules.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, TypedDict

logger = logging.getLogger(__name__)


class AIScope(TypedDict):
    pod_names: set[str]           # inventoried AI pod names (any namespace)
    namespaces: set[str]          # namespaces that contain at least one AI asset
    service_accounts: set[str]    # "<ns>/<sa>" strings for AI workloads
    deployment_names: set[str]    # inventoried AI deployment/statefulset/daemonset names
    service_names: set[str]       # inventoried AI k8s Service names


_ATLAS = {
    "pod_exec":        "AML.T0011",
    "port_forward":    "AML.T0011",
    "proxy":           "AML.T0011",
    "secret_access":   "AML.T0037",
    "secret_mutation": "AML.T0037",
    "webhook":         "AML.T0037",
    "impersonation":   "AML.T0012",
    "privileged_pod":  "AML.T0012",
    "host_ns_pod":     "AML.T0012",
    "rogue_pod":       "AML.T0007",
    "rogue_ctrl":      "AML.T0007",
    "image_change":    "AML.T0010",
    "token_request":   "AML.T0021",
    "ai_sa_binding":   "AML.T0006",
    "configmap":       "AML.T0051",
    "ingress":         "AML.T0024",
    # availability / destruction
    "destruction":     "AML.T0029",
}

_AI_SECRET_PATTERNS = (
    "openai", "anthropic", "gemini", "bedrock", "azure-openai",
    "huggingface", "cohere", "mistral", "groq", "replicate",
    "langchain", "langfuse", "api-key",
)

RULE_ID_BY_THREAT_NAME = {
    "Unexpected Pod Execution over Kubernetes API": "k8s-audit-pod-exec",
    "Port-Forward to AI Workload": "k8s-audit-pod-portforward",
    "Kubernetes API Proxy to AI Workload": "k8s-audit-pod-proxy",
    "Impersonation of AI ServiceAccount": "k8s-audit-impersonate-ai-sa",
    "Privileged Pod Created in AI Namespace": "k8s-audit-privileged-pod-in-ai-ns",
    "Host-Namespace Pod in AI Namespace": "k8s-audit-host-ns-pod-in-ai-ns",
    "Unauthorized AI Secret Access": "k8s-audit-secret-access",
    "AI Secret Mutation": "k8s-audit-secret-mutation",
    "Admission Webhook Mutation": "k8s-audit-webhook-mutation",
    "AI Service Account Binding Granted": "k8s-audit-ai-sa-binding",
    "Service Account Token Harvesting": "k8s-audit-token-request",
    "Unsanctioned Pod Creation in AI Namespace": "k8s-audit-rogue-pod",
    "Unsanctioned Workload Controller in AI Namespace": "k8s-audit-rogue-controller",
    "AI Workload Image Change": "k8s-audit-ai-image-change",
    "ConfigMap Mutation in AI Namespace": "k8s-audit-configmap-mutation",
    "External Exposure of AI Service": "k8s-audit-ingress-ai-service",
    "AI Pod Deletion": "k8s-audit-ai-pod-delete",
    "AI Workload Controller Deletion": "k8s-audit-ai-deployment-delete",
    "AI Workload Scaled to Zero": "k8s-audit-ai-scale-to-zero",
    "NetworkPolicy Mutation in AI Namespace": "k8s-audit-netpol-mutation",
    "PodDisruptionBudget Removed in AI Namespace": "k8s-audit-pdb-delete",
    "ResourceQuota Mutation in AI Namespace": "k8s-audit-resourcequota-mutation",
    "AI ServiceAccount Deletion": "k8s-audit-ai-sa-delete",
    "AI Service Deletion": "k8s-audit-ai-service-delete",
    "AI Namespace Deletion": "k8s-audit-ai-namespace-delete",
}


# ─── helpers ──────────────────────────────────────────────────────────────────


def _is_system_actor(username: str) -> bool:
    prefixes = (
        "system:kube-", "system:node:", "system:serviceaccount:kube-",
        "system:apiserver", "system:kube-controller", "system:kube-scheduler",
    )
    return any(username.startswith(p) for p in prefixes)


def _derive_role(username: str, groups: list) -> str:
    if "system:masters" in groups:
        return "Kubernetes-Admin"
    if username.startswith("system:serviceaccount:"):
        parts = username.split(":")
        return f"ServiceAccount:{parts[-1]}" if len(parts) >= 4 else username
    if username.startswith("system:node:"):
        return "KubeletNode"
    return username or "Unknown"


def _subjects_reference_ai_sa(request_object: dict, ai_sa_set: set[str]) -> list[str]:
    """RoleBinding/ClusterRoleBinding subjects[] that match an inventoried AI SA."""
    matches: list[str] = []
    for subj in (request_object or {}).get("subjects", []) or []:
        if subj.get("kind") != "ServiceAccount":
            continue
        sa_ns = subj.get("namespace", "")
        sa_name = subj.get("name", "")
        key = f"{sa_ns}/{sa_name}"
        if key in ai_sa_set:
            matches.append(key)
    return matches


def _impersonated_ai_sa(event: dict, ai_sa_set: set[str]) -> str | None:
    """Return '<ns>/<sa>' if the request impersonated an inventoried AI SA."""
    impu = event.get("impersonatedUser") or {}
    name = impu.get("username", "")
    # Format: system:serviceaccount:<ns>:<name>
    if not name.startswith("system:serviceaccount:"):
        return None
    parts = name.split(":")
    if len(parts) < 4:
        return None
    key = f"{parts[2]}/{parts[3]}"
    return key if key in ai_sa_set else None


# ─── event context ────────────────────────────────────────────────────────────


@dataclass
class EventContext:
    verb: str
    resource: str
    subresource: str
    ns: str | None
    obj_name: str
    username: str
    groups: list
    source_ips: list
    audit_id: str | None
    timestamp: str
    req_obj: dict
    resource_path: str
    principal_role: str
    principal_subject: str
    evidence: dict
    raw_event: dict


def _build_ctx(event: dict) -> EventContext:
    obj         = event.get("objectRef", {})
    resource    = obj.get("resource", "")
    subresource = obj.get("subresource", "")
    user_info   = event.get("user", {})
    username    = user_info.get("username", "")
    groups      = user_info.get("groups", [])
    source_ips  = event.get("sourceIPs", [])
    audit_id    = event.get("auditID")
    ts          = event.get("stageTimestamp") or event.get("requestReceivedTimestamp", "")
    ns          = obj.get("namespace")
    obj_name    = obj.get("name", "")
    resource_path = f"{resource}/{subresource}" if subresource else resource

    evidence = {
        "audit_id": audit_id, "verb": event.get("verb", ""),
        "resource": resource_path, "namespace": ns,
        "object_name": obj_name, "user": username,
        "source_ips": source_ips, "timestamp": ts,
    }

    return EventContext(
        verb=event.get("verb", ""),
        resource=resource,
        subresource=subresource,
        ns=ns,
        obj_name=obj_name,
        username=username,
        groups=groups,
        source_ips=source_ips,
        audit_id=audit_id,
        timestamp=ts,
        req_obj=event.get("requestObject") or {},
        resource_path=resource_path,
        principal_role=_derive_role(username, groups),
        principal_subject=obj_name,
        evidence=evidence,
        raw_event=event,
    )


def _threat(ctx: EventContext, *, threat_name: str, description: str,
            severity: str, category: str, atlas: str,
            extra_evidence: dict | None = None) -> dict:
    evidence = ctx.evidence if not extra_evidence else {**ctx.evidence, **extra_evidence}
    rule_id = RULE_ID_BY_THREAT_NAME.get(threat_name)
    if rule_id:
        evidence = {**evidence, "rule_id": rule_id}
    return {
        "rule_id": rule_id,
        "threat_name": threat_name,
        "description": description,
        "severity": severity,
        "category": category,
        "principal_role": ctx.principal_role,
        "principal_subject": ctx.principal_subject,
        "method": ctx.verb,
        "resource": ctx.resource_path,
        "namespace": ctx.ns,
        "source_ips": ctx.source_ips,
        "raw_evidence": evidence,
        "mitre_atlas": atlas,
        "audit_id": ctx.audit_id,
    }


# ─── rules — interactive access (T0011) ───────────────────────────────────────


def _r_pod_exec_or_attach(ctx: EventContext, scope: AIScope) -> dict | None:
    """Pod exec/attach/ephemeralcontainers into an inventoried AI workload."""
    if ctx.resource != "pods":
        return None
    if ctx.subresource not in ("exec", "attach", "ephemeralcontainers"):
        return None
    if ctx.obj_name not in scope["pod_names"]:
        return None
    return _threat(
        ctx,
        threat_name="Unexpected Pod Execution over Kubernetes API",
        description=(
            f"Interactive {ctx.subresource} into AI workload '{ctx.obj_name}' in ns "
            f"'{ctx.ns}' by '{ctx.username}' from {ctx.source_ips}."
        ),
        severity="critical", category="unauthorized_access", atlas=_ATLAS["pod_exec"],
    )


def _r_pod_portforward(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.resource != "pods" or ctx.subresource != "portforward":
        return None
    if ctx.obj_name not in scope["pod_names"]:
        return None
    return _threat(
        ctx,
        threat_name="Port-Forward to AI Workload",
        description=(
            f"Port-forward established to AI workload '{ctx.obj_name}' (ns '{ctx.ns}') "
            f"by '{ctx.username}'. Bypasses NetworkPolicies and exposes the workload "
            "to the operator's laptop."
        ),
        severity="high", category="unauthorized_access", atlas=_ATLAS["port_forward"],
    )


def _r_pod_proxy(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.subresource != "proxy":
        return None
    in_scope = (
        (ctx.resource == "pods" and ctx.obj_name in scope["pod_names"]) or
        (ctx.resource == "services" and ctx.obj_name in scope["service_names"])
    )
    if not in_scope:
        return None
    return _threat(
        ctx,
        threat_name="Kubernetes API Proxy to AI Workload",
        description=(
            f"API proxy request to {ctx.resource}/'{ctx.obj_name}' in ns '{ctx.ns}' "
            f"by '{ctx.username}'. Lets the caller reach AI service ports without a route."
        ),
        severity="high", category="unauthorized_access", atlas=_ATLAS["proxy"],
    )


# ─── rules — privilege escalation (T0012) ─────────────────────────────────────


def _r_impersonation_of_ai_sa(ctx: EventContext, scope: AIScope) -> dict | None:
    key = _impersonated_ai_sa(ctx.raw_event, scope["service_accounts"])
    if not key:
        return None
    return _threat(
        ctx,
        threat_name="Impersonation of AI ServiceAccount",
        description=(
            f"'{ctx.username}' invoked the API with --as impersonating AI SA '{key}'. "
            "Equivalent to holding that SA's token — direct path to AI workload privileges."
        ),
        severity="critical", category="unauthorized_access", atlas=_ATLAS["impersonation"],
        extra_evidence={"impersonated": key},
    )


def _r_privileged_pod_in_ai_ns(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb != "create" or ctx.resource != "pods" or ctx.subresource:
        return None
    if ctx.ns not in scope["namespaces"]:
        return None
    spec = (ctx.req_obj.get("spec") or {})
    containers = (spec.get("containers") or []) + (spec.get("initContainers") or [])
    privileged = any(
        (c.get("securityContext") or {}).get("privileged") is True for c in containers
    )
    if not privileged:
        return None
    return _threat(
        ctx,
        threat_name="Privileged Pod Created in AI Namespace",
        description=(
            f"Privileged pod created in AI namespace '{ctx.ns}' by '{ctx.username}'. "
            "A privileged container can break out to the node and reach any AI workload on it."
        ),
        severity="high", category="unauthorized_access", atlas=_ATLAS["privileged_pod"],
    )


def _r_host_ns_pod_in_ai_ns(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb != "create" or ctx.resource != "pods" or ctx.subresource:
        return None
    if ctx.ns not in scope["namespaces"]:
        return None
    spec = (ctx.req_obj.get("spec") or {})
    flags = {
        "hostNetwork": spec.get("hostNetwork") is True,
        "hostPID":     spec.get("hostPID") is True,
        "hostIPC":     spec.get("hostIPC") is True,
    }
    set_flags = [k for k, v in flags.items() if v]
    if not set_flags:
        return None
    return _threat(
        ctx,
        threat_name="Host-Namespace Pod in AI Namespace",
        description=(
            f"Pod with {', '.join(set_flags)} created in AI namespace '{ctx.ns}' "
            f"by '{ctx.username}'. Shares the node's kernel namespaces — can sniff or "
            "interfere with other AI workloads on the node."
        ),
        severity="high", category="unauthorized_access", atlas=_ATLAS["host_ns_pod"],
        extra_evidence={"host_namespaces": set_flags},
    )


# ─── rules — credential access (T0037) ────────────────────────────────────────


def _r_secret_access(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb not in ("get", "list") or ctx.resource != "secrets":
        return None
    name_matches = (
        any(p in ctx.obj_name.lower() for p in _AI_SECRET_PATTERNS) if ctx.obj_name else False
    )
    in_ai_ns = ctx.ns in scope["namespaces"] if ctx.ns else False
    if not (name_matches or in_ai_ns):
        return None
    return _threat(
        ctx,
        threat_name="Unauthorized AI Secret Access",
        description=(
            f"Secret {ctx.verb} on '{ctx.obj_name or '*'}' in ns '{ctx.ns}' by "
            f"'{ctx.username}'. Credential harvesting against AI API keys is a "
            "primary AISPM signal."
        ),
        severity="high" if name_matches else "medium",
        category="data_exfiltration", atlas=_ATLAS["secret_access"],
    )


def _r_secret_mutation(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb not in ("create", "update", "patch", "delete") or ctx.resource != "secrets":
        return None
    name_matches = (
        any(p in ctx.obj_name.lower() for p in _AI_SECRET_PATTERNS) if ctx.obj_name else False
    )
    in_ai_ns = ctx.ns in scope["namespaces"] if ctx.ns else False
    if not (name_matches or in_ai_ns):
        return None
    return _threat(
        ctx,
        threat_name="AI Secret Mutation",
        description=(
            f"Secret {ctx.verb} on '{ctx.obj_name}' in ns '{ctx.ns}' by '{ctx.username}'. "
            "Rewriting an AI credential lets an attacker swap upstream providers or "
            "destroy recovery state."
        ),
        severity="high", category="data_exfiltration", atlas=_ATLAS["secret_mutation"],
    )


def _r_webhook_mutation(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb not in ("create", "update", "patch"):
        return None
    if ctx.resource not in ("mutatingwebhookconfigurations", "validatingwebhookconfigurations"):
        return None
    # A cluster-wide webhook sits in the mutation path for every AI resource. Any
    # new/modified webhook is noteworthy — ship the evidence and let the analyst
    # judge. The trusted-installer filter already suppresses GitOps-managed ones.
    return _threat(
        ctx,
        threat_name="Admission Webhook Mutation",
        description=(
            f"{ctx.verb} on {ctx.resource} '{ctx.obj_name}' by '{ctx.username}'. "
            "Webhooks intercept resource mutations cluster-wide — a hostile webhook can "
            "steal Secrets and rewrite AI pod specs on admission."
        ),
        severity="high", category="supply_chain", atlas=_ATLAS["webhook"],
    )


# ─── rules — persistence / rogue workloads (T0007) ────────────────────────────


def _r_rogue_pod(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb != "create" or ctx.resource != "pods" or ctx.subresource:
        return None
    if ctx.ns not in scope["namespaces"]:
        return None
    owner_refs = (ctx.req_obj.get("metadata") or {}).get("ownerReferences") or []
    if owner_refs:
        return None
    return _threat(
        ctx,
        threat_name="Unsanctioned Pod Creation in AI Namespace",
        description=(
            f"Pod created directly (no ownerReference) in AI namespace '{ctx.ns}' "
            f"by '{ctx.username}'. Possible rogue workload injection bypassing controllers."
        ),
        severity="medium", category="model_abuse", atlas=_ATLAS["rogue_pod"],
    )


def _r_rogue_controller_workload(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb != "create":
        return None
    if ctx.resource not in ("deployments", "statefulsets", "daemonsets", "jobs", "cronjobs"):
        return None
    if ctx.ns not in scope["namespaces"]:
        return None
    return _threat(
        ctx,
        threat_name="Unsanctioned Workload Controller in AI Namespace",
        description=(
            f"{ctx.resource[:-1]} '{ctx.obj_name}' created in AI namespace '{ctx.ns}' "
            f"by '{ctx.username}'. New workload controllers in an AI namespace can "
            "run rogue agents or exfiltration loops — expect controllers to be "
            "installed by GitOps, not interactively."
        ),
        severity="medium", category="model_abuse", atlas=_ATLAS["rogue_ctrl"],
    )


# ─── rules — ML supply chain (T0010) ──────────────────────────────────────────


def _r_ai_image_change(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb not in ("update", "patch"):
        return None
    if ctx.resource not in ("deployments", "statefulsets", "daemonsets"):
        return None
    in_scope = (ctx.obj_name in scope["deployment_names"]) or (ctx.ns in scope["namespaces"])
    if not in_scope:
        return None
    tpl_spec = ((ctx.req_obj.get("spec") or {}).get("template") or {}).get("spec") or {}
    containers = tpl_spec.get("containers") or []
    images = [c.get("image") for c in containers if c.get("image")]
    if not images:
        return None
    return _threat(
        ctx,
        threat_name="AI Workload Image Change",
        description=(
            f"Container image updated on {ctx.resource[:-1]} '{ctx.obj_name}' in ns "
            f"'{ctx.ns}' by '{ctx.username}'. New image(s): {images}. Image swaps on an "
            "AI workload are a supply-chain signal — verify the pinned digest."
        ),
        severity="high", category="supply_chain", atlas=_ATLAS["image_change"],
        extra_evidence={"new_images": images},
    )


# ─── rules — rbac / tokens ────────────────────────────────────────────────────


def _r_ai_sa_binding(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb not in ("create", "update", "patch"):
        return None
    if ctx.resource not in ("rolebindings", "clusterrolebindings"):
        return None
    matched_sas = _subjects_reference_ai_sa(ctx.req_obj, scope["service_accounts"])
    if not matched_sas:
        return None
    role_ref = ctx.req_obj.get("roleRef", {}) or {}
    role_ref_name = role_ref.get("name", "")
    role_ref_kind = role_ref.get("kind", "")
    return _threat(
        ctx,
        threat_name="AI Service Account Binding Granted",
        description=(
            f"{ctx.verb} on {ctx.resource} '{ctx.obj_name}' by '{ctx.username}' binds AI "
            f"ServiceAccount(s) {matched_sas} to {role_ref_kind}/{role_ref_name}. "
            "Direct privilege grant to an inventoried AI workload."
        ),
        severity="high", category="unauthorized_access", atlas=_ATLAS["ai_sa_binding"],
        extra_evidence={"ai_subjects": matched_sas,
                        "role_ref": f"{role_ref_kind}/{role_ref_name}"},
    )


def _r_token_request(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.resource != "serviceaccounts" or ctx.subresource != "token":
        return None
    key = f"{ctx.ns}/{ctx.obj_name}"
    if key not in scope["service_accounts"]:
        return None
    return _threat(
        ctx,
        threat_name="Service Account Token Harvesting",
        description=(
            f"Token minted for AI ServiceAccount '{key}' by '{ctx.username}'. "
            "Token harvesting enables lateral movement to AI APIs."
        ),
        severity="medium", category="unauthorized_access", atlas=_ATLAS["token_request"],
    )


# ─── rules — exposure (T0024) ─────────────────────────────────────────────────


def _r_ingress_for_ai_service(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb not in ("create", "update", "patch"):
        return None
    if ctx.resource not in ("ingresses", "gateways", "httproutes", "virtualservices"):
        return None
    if ctx.ns not in scope["namespaces"]:
        return None
    return _threat(
        ctx,
        threat_name="External Exposure of AI Service",
        description=(
            f"{ctx.verb} on {ctx.resource} '{ctx.obj_name}' in AI namespace '{ctx.ns}' "
            f"by '{ctx.username}'. Publishing an AI service externally bypasses the "
            "cluster's default private posture — verify authn/authz."
        ),
        severity="high", category="anomalous_api_usage", atlas=_ATLAS["ingress"],
    )


# ─── rules — prompt/config injection (T0051) ──────────────────────────────────


def _r_configmap_mutation_in_ai_ns(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb not in ("create", "update", "patch") or ctx.resource != "configmaps":
        return None
    if ctx.ns not in scope["namespaces"]:
        return None
    return _threat(
        ctx,
        threat_name="ConfigMap Mutation in AI Namespace",
        description=(
            f"ConfigMap '{ctx.obj_name}' {ctx.verb} in AI namespace '{ctx.ns}' by "
            f"'{ctx.username}'. ConfigMaps frequently carry system prompts, tool configs "
            "and model parameters — a mutation path for indirect prompt injection."
        ),
        severity="medium", category="prompt_injection", atlas=_ATLAS["configmap"],
    )


# ─── rules — availability / destruction (T0029) ───────────────────────────────


def _r_ai_pod_delete(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb not in ("delete", "deletecollection") or ctx.resource != "pods" or ctx.subresource:
        return None
    if ctx.obj_name not in scope["pod_names"]:
        return None
    return _threat(
        ctx,
        threat_name="AI Pod Deletion",
        description=(
            f"AI workload pod '{ctx.obj_name}' deleted in ns '{ctx.ns}' by "
            f"'{ctx.username}'. Disruption to inventoried AI runtime."
        ),
        severity="high", category="availability", atlas=_ATLAS["destruction"],
    )


def _r_ai_deployment_delete(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb != "delete":
        return None
    if ctx.resource not in ("deployments", "statefulsets", "daemonsets"):
        return None
    in_scope = (ctx.obj_name in scope["deployment_names"]) or (ctx.ns in scope["namespaces"])
    if not in_scope:
        return None
    return _threat(
        ctx,
        threat_name="AI Workload Controller Deletion",
        description=(
            f"{ctx.resource[:-1]} '{ctx.obj_name}' deleted in AI namespace '{ctx.ns}' "
            f"by '{ctx.username}'. Destroys the desired-state for an AI workload."
        ),
        severity="high", category="availability", atlas=_ATLAS["destruction"],
    )


def _r_ai_scale_to_zero(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb not in ("update", "patch"):
        return None
    if ctx.resource not in ("deployments", "statefulsets"):
        return None
    in_scope = (ctx.obj_name in scope["deployment_names"]) or (ctx.ns in scope["namespaces"])
    if not in_scope:
        return None
    spec = ctx.req_obj.get("spec") or {}
    replicas = spec.get("replicas")
    try:
        if replicas is None or int(replicas) != 0:
            return None
    except (TypeError, ValueError):
        return None
    return _threat(
        ctx,
        threat_name="AI Workload Scaled to Zero",
        description=(
            f"{ctx.resource[:-1]} '{ctx.obj_name}' in AI namespace '{ctx.ns}' scaled to 0 "
            f"by '{ctx.username}'. Soft-deletion that silences AI capacity without "
            "deleting the object."
        ),
        severity="high", category="availability", atlas=_ATLAS["destruction"],
    )


def _r_netpol_mutation_in_ai_ns(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb not in ("delete", "deletecollection", "update", "patch"):
        return None
    if ctx.resource != "networkpolicies":
        return None
    if ctx.ns not in scope["namespaces"]:
        return None
    return _threat(
        ctx,
        threat_name="NetworkPolicy Mutation in AI Namespace",
        description=(
            f"NetworkPolicy '{ctx.obj_name}' {ctx.verb} in AI namespace '{ctx.ns}' "
            f"by '{ctx.username}'. Loosening or removing egress/ingress isolation around "
            "AI workloads opens exfiltration paths."
        ),
        severity="high", category="availability", atlas=_ATLAS["destruction"],
    )


def _r_pdb_delete_in_ai_ns(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb not in ("delete", "deletecollection") or ctx.resource != "poddisruptionbudgets":
        return None
    if ctx.ns not in scope["namespaces"]:
        return None
    return _threat(
        ctx,
        threat_name="PodDisruptionBudget Removed in AI Namespace",
        description=(
            f"PDB '{ctx.obj_name}' deleted in AI namespace '{ctx.ns}' by '{ctx.username}'. "
            "Enables full-eviction DoS of AI workloads during node drains."
        ),
        severity="medium", category="availability", atlas=_ATLAS["destruction"],
    )


def _r_resourcequota_mutation_in_ai_ns(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb not in ("delete", "deletecollection", "update", "patch"):
        return None
    if ctx.resource != "resourcequotas":
        return None
    if ctx.ns not in scope["namespaces"]:
        return None
    return _threat(
        ctx,
        threat_name="ResourceQuota Mutation in AI Namespace",
        description=(
            f"ResourceQuota '{ctx.obj_name}' {ctx.verb} in AI namespace '{ctx.ns}' "
            f"by '{ctx.username}'. Enables runaway-cost or cryptomining loads under "
            "the AI workload's identity."
        ),
        severity="medium", category="availability", atlas=_ATLAS["destruction"],
    )


def _r_ai_sa_delete(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb != "delete" or ctx.resource != "serviceaccounts" or ctx.subresource:
        return None
    key = f"{ctx.ns}/{ctx.obj_name}"
    if key not in scope["service_accounts"]:
        return None
    return _threat(
        ctx,
        threat_name="AI ServiceAccount Deletion",
        description=(
            f"AI ServiceAccount '{key}' deleted by '{ctx.username}'. Strips the "
            "workload's identity — next pod start fails, and token-referencing "
            "Secrets become orphans."
        ),
        severity="high", category="availability", atlas=_ATLAS["destruction"],
    )


def _r_ai_service_delete(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb != "delete" or ctx.resource != "services" or ctx.subresource:
        return None
    in_scope = (ctx.obj_name in scope["service_names"]) or (ctx.ns in scope["namespaces"])
    if not in_scope:
        return None
    return _threat(
        ctx,
        threat_name="AI Service Deletion",
        description=(
            f"Service '{ctx.obj_name}' deleted in AI namespace '{ctx.ns}' by "
            f"'{ctx.username}'. Breaks in-cluster routing to the AI workload."
        ),
        severity="high", category="availability", atlas=_ATLAS["destruction"],
    )


def _r_ai_namespace_delete(ctx: EventContext, scope: AIScope) -> dict | None:
    if ctx.verb != "delete" or ctx.resource != "namespaces":
        return None
    if ctx.obj_name not in scope["namespaces"]:
        return None
    return _threat(
        ctx,
        threat_name="AI Namespace Deletion",
        description=(
            f"Namespace '{ctx.obj_name}' deleted by '{ctx.username}'. Cascades to every "
            "AI workload, Secret, and binding in the namespace — broadest destructive "
            "action against AI posture."
        ),
        severity="critical", category="availability", atlas=_ATLAS["destruction"],
    )


# ─── dispatch ─────────────────────────────────────────────────────────────────


RuleFn = Callable[[EventContext, AIScope], "dict | None"]

# Order matters only for first-match-wins tie-breakers. Interactive/privileged
# rules go first so they aren't masked by a lower-severity rule that also matches.
_RULES: list[RuleFn] = [
    # T0011 — interactive access
    _r_pod_exec_or_attach,
    _r_pod_portforward,
    _r_pod_proxy,
    # T0012 — privilege escalation
    _r_impersonation_of_ai_sa,
    _r_privileged_pod_in_ai_ns,
    _r_host_ns_pod_in_ai_ns,
    # T0037 — credential access
    _r_secret_access,
    _r_secret_mutation,
    _r_webhook_mutation,
    # T0007 — rogue workloads
    _r_rogue_pod,
    _r_rogue_controller_workload,
    # T0010 — supply chain
    _r_ai_image_change,
    # RBAC / tokens
    _r_ai_sa_binding,
    _r_token_request,
    # T0024 — exposure
    _r_ingress_for_ai_service,
    # T0051 — prompt/config injection
    _r_configmap_mutation_in_ai_ns,
    # T0029 — destruction / availability
    _r_ai_pod_delete,
    _r_ai_deployment_delete,
    _r_ai_scale_to_zero,
    _r_netpol_mutation_in_ai_ns,
    _r_pdb_delete_in_ai_ns,
    _r_resourcequota_mutation_in_ai_ns,
    _r_ai_sa_delete,
    _r_ai_service_delete,
    _r_ai_namespace_delete,
]


def evaluate(event: dict, ai_scope: AIScope) -> dict | None:
    """Return a threat dict ready for persistence, or None."""
    if event.get("stage") != "ResponseComplete":
        return None
    if event.get("responseStatus", {}).get("code", 200) >= 400:
        return None

    ctx = _build_ctx(event)
    if _is_system_actor(ctx.username):
        return None

    for rule in _RULES:
        try:
            hit = rule(ctx, ai_scope)
        except Exception as e:
            logger.warning("Rule %s failed: %s", rule.__name__, e)
            continue
        if hit:
            return hit
    return None
