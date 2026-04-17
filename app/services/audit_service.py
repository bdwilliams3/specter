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
from app.services.ws_manager import ws_manager as manager
from app.services.trusted_installers import trusted_installers

logger = logging.getLogger(__name__)


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
        select(AIAsset.name, AIAsset.id, AIAsset.namespace, AIAsset.metadata_, AIAsset.asset_type)
    )
    rows = result.all()
    ai_pod_names: set[str] = set()
    ai_namespaces: set[str] = set()
    ai_service_accounts: set[str] = set()
    ai_deployment_names: set[str] = set()
    ai_service_names: set[str] = set()
    name_to_id: dict[str, str] = {}
    for r in rows:
        name_to_id[r.name] = r.id
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

        # Correlate to an asset if possible
        obj_name = event.get("objectRef", {}).get("name", "")
        asset_id = name_to_id.get(obj_name)

        try:
            threat_name = threat_dict["threat_name"]
            threat = ThreatEvent(
                asset_id=asset_id,
                threat_name=threat_name,
                title=threat_name,
                description=threat_dict["description"],
                severity=ThreatSeverity(threat_dict["severity"]),
                category=ThreatCategory(threat_dict["category"]),
                principal_role=threat_dict.get("principal_role"),
                principal_subject=threat_dict.get("principal_subject"),
                method=threat_dict.get("method"),
                resource=threat_dict.get("resource"),
                namespace=threat_dict.get("namespace"),
                source_ips=threat_dict.get("source_ips"),
                raw_evidence=threat_dict.get("raw_evidence", {}),
                mitre_atlas=threat_dict.get("mitre_atlas"),
                audit_id=threat_dict.get("audit_id"),
                detected_at=datetime.utcnow(),
                scan_run_id=scan_run_id,
            )
            db.add(threat)
            await db.flush()
            new_threats += 1

            # Broadcast via WebSocket
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
