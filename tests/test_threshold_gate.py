import asyncio
import os
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

os.environ.setdefault("SQLITE_PATH", str(Path(__file__).parent / "test_specter.db"))

from app.database import Base
from app.models.asset import AIAsset, AssetType
from app.models.rule_config import RuleConfig
from app.models.threat import ThreatEvent
from app.services import audit_service


class BroadcastRecorder:
    def __init__(self):
        self.messages = []

    async def broadcast(self, message):
        self.messages.append(message)


def run(coro):
    return asyncio.run(coro)


async def make_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, session_factory()


def secret_access_event(audit_id="audit-1"):
    return {
        "auditID": audit_id,
        "stage": "ResponseComplete",
        "verb": "get",
        "user": {"username": "alice@example.com", "groups": ["devs"]},
        "sourceIPs": ["10.0.0.10"],
        "objectRef": {
            "resource": "secrets",
            "namespace": "workload",
            "name": "plain-secret",
        },
        "responseStatus": {"code": 200},
        "stageTimestamp": "2026-04-29T12:00:00Z",
    }


async def insert_asset_and_config(session, confidence):
    session.add(
        AIAsset(
            name="ai-pod",
            asset_type=AssetType.k8s_pod,
            provider="k8s",
            namespace="workload",
            ai_confidence=confidence,
            metadata_={"service_account": "ai-sa"},
        )
    )
    session.add(
        RuleConfig(
            rule_id="k8s-audit-secret-access",
            min_asset_confidence=5,
            enabled=True,
        )
    )
    await session.commit()


def test_threshold_suppresses_low_confidence_namespace_scoped_rule(monkeypatch):
    async def scenario():
        recorder = BroadcastRecorder()
        monkeypatch.setattr(audit_service, "manager", recorder)
        engine, session = await make_session()
        try:
            await insert_asset_and_config(session, confidence=3.0)
            count = await audit_service.process_audit_events([secret_access_event()], session)
            threat = (await session.execute(select(ThreatEvent))).scalar_one()
            assert count == 1
            assert threat.suppressed is True
            assert "below rule threshold 5" in threat.suppression_reason
            assert threat.raw_evidence["asset_confidence"] == 3.0
            assert recorder.messages == []
        finally:
            await session.close()
            await engine.dispose()

    run(scenario())


def test_raising_confidence_unsuppresses_on_next_fire(monkeypatch):
    async def scenario():
        recorder = BroadcastRecorder()
        monkeypatch.setattr(audit_service, "manager", recorder)
        engine, session = await make_session()
        try:
            await insert_asset_and_config(session, confidence=7.0)
            count = await audit_service.process_audit_events([secret_access_event()], session)
            threat = (await session.execute(select(ThreatEvent))).scalar_one()
            assert count == 1
            assert threat.suppressed is False
            assert threat.suppression_reason is None
            assert len(recorder.messages) == 1
        finally:
            await session.close()
            await engine.dispose()

    run(scenario())


def test_cluster_scoped_rules_do_not_use_namespace_fallback(monkeypatch):
    async def scenario():
        recorder = BroadcastRecorder()
        monkeypatch.setattr(audit_service, "manager", recorder)
        engine, session = await make_session()
        try:
            await insert_asset_and_config(session, confidence=3.0)
            session.add(
                RuleConfig(
                    rule_id="k8s-audit-webhook-mutation",
                    min_asset_confidence=5,
                    enabled=True,
                )
            )
            await session.commit()
            event = {
                "auditID": "audit-webhook",
                "stage": "ResponseComplete",
                "verb": "patch",
                "user": {"username": "alice@example.com", "groups": ["devs"]},
                "sourceIPs": ["10.0.0.10"],
                "objectRef": {
                    "resource": "mutatingwebhookconfigurations",
                    "name": "admission-hook",
                },
                "responseStatus": {"code": 200},
                "stageTimestamp": "2026-04-29T12:00:00Z",
            }
            await audit_service.process_audit_events([event], session)
            threat = (
                await session.execute(
                    select(ThreatEvent).where(ThreatEvent.audit_id == "audit-webhook")
                )
            ).scalar_one()
            assert threat.suppressed is False
            assert len(recorder.messages) == 1
        finally:
            await session.close()
            await engine.dispose()

    run(scenario())
