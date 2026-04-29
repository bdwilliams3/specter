import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database import Base
from app.models.asset import AIAsset, AssetType
from app.models.asset_triage import AssetTriageAudit
from app.services.asset_triage import apply_asset_triage, effective_confidence


def run(coro):
    return asyncio.run(coro)


async def make_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, session_factory()


def test_downgrade_sets_confidence_ceiling_and_audit_row():
    async def scenario():
        engine, session = await make_session()
        try:
            asset = AIAsset(
                name="agent",
                asset_type=AssetType.agentic_framework,
                provider="k8s",
                namespace="workload",
                ai_confidence=8.7,
            )
            session.add(asset)
            await session.commit()

            await apply_asset_triage(session, asset, "downgrade", "known legacy agent", "alice", 5.0)
            audit = (await session.execute(select(AssetTriageAudit))).scalar_one()

            assert asset.triage_state == "downgraded"
            assert effective_confidence(asset) == 5.0
            assert audit.action == "downgrade"
            assert audit.reason == "known legacy agent"
        finally:
            await session.close()
            await engine.dispose()

    run(scenario())
