"""
Processes k8s audit event batches: enrich, evaluate rules, persist threats, broadcast.
Called by both the webhook collector and the log-tail scanner.
"""
import logging
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import AIAsset
from app.models.threat import ThreatEvent, ThreatSeverity, ThreatCategory
from app.detectors.threat_rules import evaluate
from app.services.rule_config import get_rule_config_map
from app.services.ws_manager import ws_manager as manager
from app.services.trusted_installers import trusted_installers

logger = logging.getLogger(__name__)

NAMESPACE_SCOPED_RESOURCES = {
    "bindings",
    "configmaps",
    "cronjobs",
    "daemonsets",
    "deployments",
    "endpoints",
    "events",
    "ingresses",
    "jobs",
    "networkpolicies",
    "persistentvolumeclaims",
    "pods",
    "poddisruptionbudgets",
    "replicasets",
    "replicationcontrollers",
    "resourcequotas",
    "rolebindings",
    "roles",
    "secrets",
    "serviceaccounts",
    "services",
    "statefulsets",
}


def _asset_confidence(row) -> float:
    confidence = getattr(row, "ai_confidence", None)
    if confidence is None:
        confidence = getattr(row, "risk_score", 0) or 0
    ceiling = getattr(row, "confidence_ceiling", None)
    if ceiling is not None:
        confidence = min(float(confidence), float(ceiling))
    return float(confidence)


def _event_asset_confidence(event: dict, name_to_confidence: dict[tuple[str, str | None], float],
                            ns_max_confidence: dict[str, float]) -> float | None:
    obj = event.get("objectRef", {}) or {}
    obj_name = obj.get("name", "")
    namespace = obj.get("namespace")
    resource = obj.get("resource", "")
    if obj_name:
        direct = name_to_confidence.get((obj_name, namespace))
        if direct is not None:
            return direct
    if namespace and resource in NAMESPACE_SCOPED_RESOURCES:
        return ns_max_confidence.get(namespace)
    return None


async def process_audit_events(events: list[dict], db: AsyncSession, scan_run_id: str | None = None) -> int:
    """
    Process a batch of k8s audit events.
    Returns the number of new threats persisted.
    """
    if not events:
        return 0

    # Build the AI scope from inventory — the source of truth for rule gating.
    # Every rule in threat_rules.py checks whether the event's target falls
    # within this scope. If inventory is empty, no audit-based rule fires.
    result = await db.execute(
        select(AIAsset.name, AIAsset.id, AIAsset.namespace, AIAsset.metadata_, AIAsset.asset_type,
               AIAsset.ai_confidence, AIAsset.risk_score, AIAsset.triage_state,
               AIAsset.triage_reason, AIAsset.confidence_ceiling)
    )
    rows = result.all()
    ai_pod_names: set[str] = set()
    ai_namespaces: set[str] = set()
    ai_service_accounts: set[str] = set()
    ai_deployment_names: set[str] = set()
    ai_service_names: set[str] = set()
    name_to_id: dict[tuple[str, str | None], str] = {}
    name_to_confidence: dict[tuple[str, str | None], float] = {}
    name_to_triage: dict[tuple[str, str | None], tuple[str | None, str | None]] = {}
    ns_max_confidence: dict[str, float] = {}
    for r in rows:
        asset_key = (r.name, r.namespace)
        name_to_id[asset_key] = r.id
        confidence = _asset_confidence(r)
        name_to_confidence[asset_key] = confidence
        name_to_triage[asset_key] = (r.triage_state, r.triage_reason)
        if r.namespace and r.triage_state != "dismissed":
            ns_max_confidence[r.namespace] = max(ns_max_confidence.get(r.namespace, 0.0), confidence)
        at = r.asset_type.value if hasattr(r.asset_type, "value") else str(r.asset_type)
        # Pod-level assets (agents, mcp servers, model servers)
        if at in ("agentic_framework", "mcp_server", "model_server", "k8s_pod"):
            ai_pod_names.add(r.name)
        # Controller-level assets — used by image-change / delete / scale-to-zero rules
        if at == "k8s_deployment":
            ai_deployment_names.add(r.name)
        # Service-level assets — used by proxy / service-delete rules
        if at == "k8s_service":
            ai_service_names.add(r.name)
        if r.namespace:
            ai_namespaces.add(r.namespace)
        sa = (r.metadata_ or {}).get("service_account")
        if sa and r.namespace:
            ai_service_accounts.add(f"{r.namespace}/{sa}")

    rule_configs = await get_rule_config_map(db)

    ai_scope = {
        "pod_names": ai_pod_names,
        "namespaces": ai_namespaces,
        "service_accounts": ai_service_accounts,
        "deployment_names": ai_deployment_names,
        "service_names": ai_service_names,
    }

    # Load already-processed audit IDs to deduplicate
    audit_ids = [e.get("auditID") for e in events if e.get("auditID")]
    existing = set()
    if audit_ids:
        res = await db.execute(
            select(ThreatEvent.audit_id).where(ThreatEvent.audit_id.in_(audit_ids))
        )
        existing = {r[0] for r in res.all()}

    new_threats = 0
    for event in events:
        aid = event.get("auditID")
        if aid and aid in existing:
            continue

        # Trusted installer filter — known-safe automation principals (GitOps
        # controllers, CI pipelines, OpenShift operators) routinely mutate
        # Roles, RoleBindings, Deployments, etc. Those events are suppressed.
        #
        # But trust is SCOPED: interactive and credential-sensitive subresources
        # (pods/exec, pods/attach, serviceaccounts/token, ...) are never
        # suppressed — no legitimate automation execs into an AI workload or
        # mints a foreign SA token. A compromised pipeline SA looks exactly
        # like an attacker at that point.
        username = event.get("user", {}).get("username", "")
        verb = event.get("verb", "")
        subres = event.get("objectRef", {}).get("subresource", "")
        is_mutation = verb in {"create", "update", "patch", "delete", "deletecollection"}
        is_sensitive_subres = subres in {"exec", "attach", "portforward", "proxy", "token"}
        if trusted_installers.is_trusted(username) and is_mutation and not is_sensitive_subres:
            continue

        threat_dict = evaluate(event, ai_scope)
        if not threat_dict:
            continue

        rule_id = threat_dict.get("rule_id") or (threat_dict.get("raw_evidence") or {}).get("rule_id")
        rule_config = rule_configs.get(rule_id) if rule_id else None
        if rule_config and not rule_config.enabled:
            continue

        # Correlate to an asset if possible
        obj = event.get("objectRef", {}) or {}
        obj_name = obj.get("name", "")
        obj_ns = obj.get("namespace")
        asset_id = name_to_id.get((obj_name, obj_ns))
        triage_state, triage_reason = name_to_triage.get((obj_name, obj_ns), (None, None))

        suppressed = False
        suppression_reason = None
        asset_confidence = _event_asset_confidence(event, name_to_confidence, ns_max_confidence)
        min_confidence = int(rule_config.min_asset_confidence) if rule_config else 0
        if min_confidence > 0 and asset_confidence is not None and asset_confidence < min_confidence:
            suppressed = True
            suppression_reason = (
                f"asset confidence {asset_confidence:.1f} is below rule threshold "
                f"{min_confidence}"
            )
            threat_dict["raw_evidence"] = {
                **threat_dict.get("raw_evidence", {}),
                "asset_confidence": asset_confidence,
                "min_asset_confidence": min_confidence,
                "suppression_reason": suppression_reason,
            }
            threat_dict["suppressed"] = True
            threat_dict["suppression_reason"] = suppression_reason
        if triage_state == "dismissed":
            suppressed = True
            suppression_reason = f"asset dismissed by analyst: {triage_reason or 'no reason recorded'}"
            threat_dict["raw_evidence"] = {
                **threat_dict.get("raw_evidence", {}),
                "suppression_reason": suppression_reason,
            }
            threat_dict["suppressed"] = True
            threat_dict["suppression_reason"] = suppression_reason

        severity = rule_config.severity_override if rule_config and rule_config.severity_override else threat_dict["severity"]

        try:
            threat_name = threat_dict["threat_name"]
            threat = ThreatEvent(
                asset_id=asset_id,
                threat_name=threat_name,
                title=threat_name,
                description=threat_dict["description"],
                severity=ThreatSeverity(severity),
                category=ThreatCategory(threat_dict["category"]),
                principal_role=threat_dict.get("principal_role"),
                principal_subject=threat_dict.get("principal_subject"),
                method=threat_dict.get("method"),
                resource=threat_dict.get("resource"),
                namespace=threat_dict.get("namespace"),
                source_ips=threat_dict.get("source_ips"),
                raw_evidence=threat_dict.get("raw_evidence", {}),
                suppressed=suppressed,
                suppression_reason=suppression_reason,
                mitre_atlas=threat_dict.get("mitre_atlas"),
                audit_id=threat_dict.get("audit_id"),
                detected_at=datetime.utcnow(),
                scan_run_id=scan_run_id,
            )
            db.add(threat)
            await db.flush()
            new_threats += 1

            # Broadcast via WebSocket
            if not suppressed:
                await manager.broadcast({
                    "type": "threat",
                    "id": threat.id,
                    "title": threat.title,
                    "severity": threat.severity.value,
                    "category": threat.category.value,
                    "detected_at": threat.detected_at.isoformat(),
                })

            if aid:
                existing.add(aid)

        except Exception as e:
            logger.warning("Failed to persist threat: %s", e)

    if new_threats:
        await db.commit()
        logger.info("Persisted %d new threats from %d audit events", new_threats, len(events))

    return new_threats
