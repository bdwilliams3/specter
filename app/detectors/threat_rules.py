"""
Audit-event-based threat detection rules.

evaluate() takes a single k8s audit event dict and returns a threat dict or None.
Evaluated only against stage=ResponseComplete with successful response codes.

Rule names are intentionally broad — they describe a class of behavior, not a specific
instance. Structured fields (principal_role, method, resource, etc.) carry the context
needed for scoping and filtering.
"""
import logging

logger = logging.getLogger(__name__)

AI_NAMESPACES = {"workload", "specter"}

_ATLAS = {
    "pod_exec":      "AML.T0011",
    "secret_access": "AML.T0037",
    "rbac_mutation": "AML.T0006",
    "rogue_pod":     "AML.T0007",
    "token_request": "AML.T0021",
}


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


def _bump(sev: str, ns: str | None) -> str:
    if ns in AI_NAMESPACES:
        return {"low": "medium", "medium": "high", "high": "critical"}.get(sev, sev)
    return sev


def evaluate(event: dict, ai_asset_names: set[str]) -> dict | None:
    """Return a threat dict ready for persistence, or None."""
    if event.get("stage") != "ResponseComplete":
        return None
    if event.get("responseStatus", {}).get("code", 200) >= 400:
        return None

    verb        = event.get("verb", "")
    obj         = event.get("objectRef", {})
    resource    = obj.get("resource", "")
    subresource = obj.get("subresource", "")
    ns          = obj.get("namespace")
    obj_name    = obj.get("name", "")
    user_info   = event.get("user", {})
    username    = user_info.get("username", "")
    groups      = user_info.get("groups", [])
    source_ips  = event.get("sourceIPs", [])
    audit_id    = event.get("auditID")
    ts          = event.get("stageTimestamp") or event.get("requestReceivedTimestamp", "")

    if _is_system_actor(username):
        return None

    principal_role    = _derive_role(username, groups)
    principal_subject = obj_name
    resource_path     = f"{resource}/{subresource}" if subresource else resource

    evidence = {
        "audit_id": audit_id, "verb": verb,
        "resource": resource_path, "namespace": ns,
        "object_name": obj_name, "user": username,
        "source_ips": source_ips, "timestamp": ts,
    }

    # Rule 1 — Pod exec / attach
    if verb in ("create", "get") and resource == "pods" and subresource in ("exec", "attach"):
        sev = "critical" if obj_name in ai_asset_names else _bump("high", ns)
        return {
            "threat_name": "Unexpected Pod Execution over Kubernetes API",
            "description": (
                f"Interactive exec/attach into pod '{obj_name}' in ns '{ns}' "
                f"by '{username}' from {source_ips}."
            ),
            "severity": sev, "category": "unauthorized_access",
            "principal_role": principal_role, "principal_subject": principal_subject,
            "method": verb, "resource": resource_path,
            "namespace": ns, "source_ips": source_ips,
            "raw_evidence": evidence, "mitre_atlas": _ATLAS["pod_exec"], "audit_id": audit_id,
        }

    # Rule 2 — Secret access
    if verb in ("get", "list") and resource == "secrets":
        sev = _bump("medium", ns)
        ai_patterns = ("api-key", "openai", "anthropic", "gemini", "bedrock", "azure")
        if any(p in obj_name.lower() for p in ai_patterns):
            sev = "high"
        return {
            "threat_name": "Unauthorized AI Secret Access",
            "description": (
                f"Secret {verb} on '{obj_name or '*'}' in ns '{ns}' by '{username}'. "
                "Credential harvesting against AI API keys is a primary AISPM signal."
            ),
            "severity": sev, "category": "data_exfiltration",
            "principal_role": principal_role, "principal_subject": principal_subject,
            "method": verb, "resource": resource_path,
            "namespace": ns, "source_ips": source_ips,
            "raw_evidence": evidence, "mitre_atlas": _ATLAS["secret_access"], "audit_id": audit_id,
        }

    # Rule 3 — RBAC mutation
    if verb in ("create", "update", "patch", "delete") and resource in (
        "clusterroles", "clusterrolebindings", "roles", "rolebindings"
    ):
        return {
            "threat_name": "Unauthorized RBAC Modification",
            "description": (
                f"Privilege escalation: {verb} on {resource} '{obj_name}' by '{username}'. "
                "RBAC mutations can grant access to AI workload secrets and APIs."
            ),
            "severity": "high", "category": "unauthorized_access",
            "principal_role": principal_role, "principal_subject": principal_subject,
            "method": verb, "resource": resource_path,
            "namespace": ns, "source_ips": source_ips,
            "raw_evidence": evidence, "mitre_atlas": _ATLAS["rbac_mutation"], "audit_id": audit_id,
        }

    # Rule 4 — Bare pod in AI namespace (no controller)
    if verb == "create" and resource == "pods" and not subresource and ns in AI_NAMESPACES:
        owner_refs = (event.get("requestObject") or {}).get("metadata", {}).get("ownerReferences", [])
        if not owner_refs:
            return {
                "threat_name": "Unsanctioned Pod Creation in AI Namespace",
                "description": (
                    f"Pod created directly (no ownerReference) in AI namespace '{ns}' by '{username}'. "
                    "Possible rogue workload injection."
                ),
                "severity": "medium", "category": "model_abuse",
                "principal_role": principal_role, "principal_subject": principal_subject,
                "method": verb, "resource": resource_path,
                "namespace": ns, "source_ips": source_ips,
                "raw_evidence": evidence, "mitre_atlas": _ATLAS["rogue_pod"], "audit_id": audit_id,
            }

    # Rule 5 — SA token request in AI namespace
    if ns in AI_NAMESPACES and (
        resource == "tokenreviews" or
        (resource == "serviceaccounts" and subresource == "token")
    ):
        return {
            "threat_name": "Service Account Token Harvesting",
            "description": (
                f"ServiceAccount token request in '{ns}' by '{username}'. "
                "Token harvesting enables lateral movement to AI APIs."
            ),
            "severity": "medium", "category": "unauthorized_access",
            "principal_role": principal_role, "principal_subject": principal_subject,
            "method": verb, "resource": resource_path,
            "namespace": ns, "source_ips": source_ips,
            "raw_evidence": evidence, "mitre_atlas": _ATLAS["token_request"], "audit_id": audit_id,
        }

    return None
