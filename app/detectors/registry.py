"""
Static registry of detection rules.

Rules are code-defined (in `threat_rules.py` and `services/network_service.py`).
This registry is the source of truth for rule *metadata* — what we display in the
UI and what we filter against. The `threat_name` field is the join key to
`threat_events.threat_name` for counting fires.

When adding a new rule:
  1. Implement it in the appropriate detector module
  2. Add a row here with the same `threat_name` string
"""

CLOUD_KUBERNETES = "kubernetes"
CLOUD_AWS        = "aws"
CLOUD_GCP        = "gcp"
CLOUD_AZURE      = "azure"
CLOUD_OPENAI     = "openai"
CLOUD_ANTHROPIC  = "anthropic"
CLOUD_IBM        = "ibm"

SUPPORTED_CLOUDS = [
    {"id": CLOUD_KUBERNETES, "label": "Kubernetes",  "enabled": True},
    {"id": CLOUD_AWS,        "label": "AWS",         "enabled": False},
    {"id": CLOUD_GCP,        "label": "GCP",         "enabled": False},
    {"id": CLOUD_AZURE,      "label": "Azure",       "enabled": False},
    {"id": CLOUD_OPENAI,     "label": "OpenAI",      "enabled": False},
    {"id": CLOUD_ANTHROPIC,  "label": "Anthropic",   "enabled": False},
    {"id": CLOUD_IBM,        "label": "IBM Cloud",   "enabled": False},
]

def _k8s_audit(rule_id: str, threat_name: str, severity: str, category: str,
               atlas: str, description: str) -> dict:
    return {
        "rule_id": rule_id, "threat_name": threat_name,
        "cloud": CLOUD_KUBERNETES, "source": "audit",
        "severity_default": severity, "category": category,
        "mitre_atlas": atlas, "description": description,
    }


def _k8s_net(rule_id: str, threat_name: str, severity: str, category: str,
             atlas: str, description: str) -> dict:
    return {
        "rule_id": rule_id, "threat_name": threat_name,
        "cloud": CLOUD_KUBERNETES, "source": "network",
        "severity_default": severity, "category": category,
        "mitre_atlas": atlas, "description": description,
    }


RULES = [
    # ── Kubernetes audit rules — interactive access (T0011) ──────────────────
    _k8s_audit("k8s-audit-pod-exec",
               "Unexpected Pod Execution over Kubernetes API",
               "critical", "unauthorized_access", "AML.T0011",
               "Interactive exec/attach/ephemeralcontainers targeting an inventoried "
               "AI workload. Non-AI pods are out of scope — AISPM signal, not KSPM."),
    _k8s_audit("k8s-audit-pod-portforward",
               "Port-Forward to AI Workload",
               "high", "unauthorized_access", "AML.T0011",
               "Port-forward to an inventoried AI pod. Bypasses NetworkPolicies and "
               "exposes the workload to an operator laptop."),
    _k8s_audit("k8s-audit-pod-proxy",
               "Kubernetes API Proxy to AI Workload",
               "high", "unauthorized_access", "AML.T0011",
               "API proxy to an AI pod or AI Service. Lets the caller reach AI "
               "ports without a routed network path."),

    # ── Privilege escalation (T0012) ─────────────────────────────────────────
    _k8s_audit("k8s-audit-impersonate-ai-sa",
               "Impersonation of AI ServiceAccount",
               "critical", "unauthorized_access", "AML.T0012",
               "Request with --as impersonating an inventoried AI ServiceAccount. "
               "Equivalent to holding that SA's token."),
    _k8s_audit("k8s-audit-privileged-pod-in-ai-ns",
               "Privileged Pod Created in AI Namespace",
               "high", "unauthorized_access", "AML.T0012",
               "Pod with a privileged container created in an AI namespace. "
               "Node breakout lets the caller reach any AI workload on the node."),
    _k8s_audit("k8s-audit-host-ns-pod-in-ai-ns",
               "Host-Namespace Pod in AI Namespace",
               "high", "unauthorized_access", "AML.T0012",
               "Pod with hostNetwork/hostPID/hostIPC in an AI namespace. Shares "
               "the node's kernel namespaces with AI workloads."),

    # ── Credential access (T0037) ────────────────────────────────────────────
    _k8s_audit("k8s-audit-secret-access",
               "Unauthorized AI Secret Access",
               "medium", "data_exfiltration", "AML.T0037",
               "Get/list on a Secret in an AI namespace, or on a Secret whose "
               "name matches an AI-provider pattern (openai, anthropic, ...)."),
    _k8s_audit("k8s-audit-secret-mutation",
               "AI Secret Mutation",
               "high", "data_exfiltration", "AML.T0037",
               "Create/update/patch/delete on an AI-scoped Secret. Credential "
               "swaps redirect the AI workload to an attacker-controlled upstream."),
    _k8s_audit("k8s-audit-webhook-mutation",
               "Admission Webhook Mutation",
               "high", "supply_chain", "AML.T0037",
               "MutatingWebhookConfiguration / ValidatingWebhookConfiguration "
               "mutation. A hostile webhook sits in the admission path for every "
               "AI resource — can steal Secrets and rewrite pod specs."),

    # ── RBAC / tokens ────────────────────────────────────────────────────────
    _k8s_audit("k8s-audit-ai-sa-binding",
               "AI Service Account Binding Granted",
               "high", "unauthorized_access", "AML.T0006",
               "Role/ClusterRoleBinding created or patched with an inventoried AI "
               "ServiceAccount as subject. Direct privilege grant to an AI workload."),
    _k8s_audit("k8s-audit-token-request",
               "Service Account Token Harvesting",
               "medium", "unauthorized_access", "AML.T0021",
               "Token minted for an inventoried AI ServiceAccount. Enables lateral "
               "movement to AI APIs."),

    # ── Rogue workloads (T0007) ──────────────────────────────────────────────
    _k8s_audit("k8s-audit-rogue-pod",
               "Unsanctioned Pod Creation in AI Namespace",
               "medium", "model_abuse", "AML.T0007",
               "Bare pod (no ownerReference) created in an AI namespace. Possible "
               "rogue-workload injection bypassing controllers."),
    _k8s_audit("k8s-audit-rogue-controller",
               "Unsanctioned Workload Controller in AI Namespace",
               "medium", "model_abuse", "AML.T0007",
               "Deployment/StatefulSet/DaemonSet/Job/CronJob created interactively "
               "in an AI namespace. Expected channel is GitOps; the trusted-installer "
               "filter suppresses those."),

    # ── Supply chain (T0010) ─────────────────────────────────────────────────
    _k8s_audit("k8s-audit-ai-image-change",
               "AI Workload Image Change",
               "high", "supply_chain", "AML.T0010",
               "Container image updated on an inventoried AI controller (or any "
               "controller in an AI namespace). Verify the pinned digest."),

    # ── Prompt / config injection (T0051) ────────────────────────────────────
    _k8s_audit("k8s-audit-configmap-mutation",
               "ConfigMap Mutation in AI Namespace",
               "medium", "prompt_injection", "AML.T0051",
               "ConfigMap create/update/patch in an AI namespace. ConfigMaps "
               "frequently carry system prompts, tool configs, model parameters."),

    # ── External exposure (T0024) ────────────────────────────────────────────
    _k8s_audit("k8s-audit-ingress-ai-service",
               "External Exposure of AI Service",
               "high", "anomalous_api_usage", "AML.T0024",
               "Ingress/Gateway/HTTPRoute/VirtualService create/update in an AI "
               "namespace. Publishes an AI service externally — verify authn/authz."),

    # ── Availability / destruction (T0029) ───────────────────────────────────
    _k8s_audit("k8s-audit-ai-pod-delete",
               "AI Pod Deletion",
               "high", "availability", "AML.T0029",
               "Delete on an inventoried AI pod. Disruption to AI runtime."),
    _k8s_audit("k8s-audit-ai-deployment-delete",
               "AI Workload Controller Deletion",
               "high", "availability", "AML.T0029",
               "Delete on a Deployment/StatefulSet/DaemonSet in an AI namespace. "
               "Destroys the desired-state for an AI workload."),
    _k8s_audit("k8s-audit-ai-scale-to-zero",
               "AI Workload Scaled to Zero",
               "high", "availability", "AML.T0029",
               "Replicas=0 on a Deployment/StatefulSet in an AI namespace. "
               "Soft-deletion that silences AI capacity."),
    _k8s_audit("k8s-audit-netpol-mutation",
               "NetworkPolicy Mutation in AI Namespace",
               "high", "availability", "AML.T0029",
               "Update/patch/delete on a NetworkPolicy in an AI namespace. "
               "Loosens egress/ingress isolation around AI workloads."),
    _k8s_audit("k8s-audit-pdb-delete",
               "PodDisruptionBudget Removed in AI Namespace",
               "medium", "availability", "AML.T0029",
               "PDB deleted in an AI namespace. Enables full-eviction DoS during drains."),
    _k8s_audit("k8s-audit-resourcequota-mutation",
               "ResourceQuota Mutation in AI Namespace",
               "medium", "availability", "AML.T0029",
               "ResourceQuota update/patch/delete in an AI namespace. Enables "
               "runaway-cost or cryptomining loads under the AI workload's identity."),
    _k8s_audit("k8s-audit-ai-sa-delete",
               "AI ServiceAccount Deletion",
               "high", "availability", "AML.T0029",
               "Inventoried AI ServiceAccount deleted. Strips the workload's identity."),
    _k8s_audit("k8s-audit-ai-service-delete",
               "AI Service Deletion",
               "high", "availability", "AML.T0029",
               "Service deleted in an AI namespace. Breaks in-cluster routing."),
    _k8s_audit("k8s-audit-ai-namespace-delete",
               "AI Namespace Deletion",
               "critical", "availability", "AML.T0029",
               "Delete on a namespace that contains inventoried AI workloads. "
               "Cascades to every AI workload, Secret and binding in the namespace."),

    # ── Kubernetes network rules (Tetragon) ──────────────────────────────────
    _k8s_net("k8s-net-lateral-movement",
             "AI Agent Lateral Movement via Internal API",
             "high", "anomalous_api_usage", "AML.T0011",
             "AI pod established a TCP connection to an internal AI/MCP port "
             "(8000, 8080, 8443, 11434, ...)."),
    _k8s_net("k8s-net-external-egress",
             "Unauthorized AI Workload External Egress",
             "high", "data_exfiltration", "AML.T0037",
             "AI pod connected to an external IP on 443/80. May indicate "
             "unsanctioned LLM usage or data exfiltration."),
    _k8s_net("k8s-net-ai-port-probing",
             "Probing of AI Service Port by Non-AI Workload",
             "medium", "anomalous_api_usage", "AML.T0040",
             "Non-inventoried pod reached an internal AI/MCP port. "
             "Reconnaissance against the AI surface area."),
    _k8s_net("k8s-net-unexpected-binary-egress",
             "AI Pod Egress by Unexpected Binary",
             "medium", "data_exfiltration", "AML.T0025",
             "AI pod egressed externally under a non-runtime binary (shell, "
             "curl, wget, custom). Classic post-exploitation exfil fingerprint."),
]
