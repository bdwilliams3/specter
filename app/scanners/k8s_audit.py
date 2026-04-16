"""
k8s_audit scanner — tails kube-apiserver stdout for audit events.

Reads the last N lines of the kube-apiserver pod log (which contains JSON
audit events when audit-log-path: "-"), parses them, and feeds them through
the audit_service threat pipeline.

Bridge scanner until the audit webhook is wired (kind-config.yaml).
"""
import json
import logging
from kubernetes import client, config as k8s_config

from app.scanners.base import BaseScanner, ScanResult
from app.database import AsyncSessionLocal
from app.services.audit_service import process_audit_events

logger = logging.getLogger(__name__)

APISERVER_POD_PREFIX = "kube-apiserver-"
KUBE_SYSTEM_NS = "kube-system"
TAIL_LINES = 1000


class K8sAuditScanner(BaseScanner):
    name = "k8s_audit"
    display_name = "Kubernetes Audit Log"

    async def scan(self, target: str, config_dict: dict) -> ScanResult:
        result = ScanResult()
        try:
            try:
                k8s_config.load_incluster_config()
            except Exception:
                k8s_config.load_kube_config()

            v1 = client.CoreV1Api()

            pods = v1.list_namespaced_pod(KUBE_SYSTEM_NS)
            apiserver_pod = next(
                (p.metadata.name for p in pods.items
                 if p.metadata.name.startswith(APISERVER_POD_PREFIX)),
                None,
            )
            if not apiserver_pod:
                logger.warning("k8s_audit: kube-apiserver pod not found")
                return result

            logger.info("k8s_audit: reading %d lines from %s", TAIL_LINES, apiserver_pod)
            logs = v1.read_namespaced_pod_log(
                name=apiserver_pod,
                namespace=KUBE_SYSTEM_NS,
                tail_lines=TAIL_LINES,
            )

            events = []
            for line in logs.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if obj.get("apiVersion", "").startswith("audit.k8s.io"):
                        events.append(obj)
                except json.JSONDecodeError:
                    continue

            logger.info("k8s_audit: parsed %d audit events", len(events))

            async with AsyncSessionLocal() as db:
                fired = await process_audit_events(events, db)
                logger.info("k8s_audit: fired %d new threats", fired)

        except Exception as e:
            logger.error("k8s_audit scanner error: %s", e)
            result.error = str(e)

        return result
