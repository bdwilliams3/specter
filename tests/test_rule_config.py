import asyncio
import os
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

os.environ.setdefault("SQLITE_PATH", str(Path(__file__).parent / "test_specter.db"))

from app.database import Base
from app.models.rule_config import RuleConfig, RuleConfigAudit
from app.services.rule_config import patch_rule_config


def run(coro):
    return asyncio.run(coro)


async def make_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, session_factory()


def test_patch_rule_config_updates_config_and_writes_audit():
    async def scenario():
        engine, session = await make_session()
        try:
            session.add(RuleConfig(rule_id="k8s-audit-secret-access"))
            await session.commit()

            config = await patch_rule_config(
                session,
                "k8s-audit-secret-access",
                {
                    "min_asset_confidence": 6,
                    "enabled": False,
                    "severity_override": "critical",
                    "route": "siem-high",
                },
                "alice@example.com",
            )

            audit = (await session.execute(select(RuleConfigAudit))).scalar_one()
            assert config.min_asset_confidence == 6
            assert config.enabled is False
            assert config.severity_override == "critical"
            assert config.route == "siem-high"
            assert config.updated_by == "alice@example.com"
            assert audit.before["min_asset_confidence"] == 0
            assert audit.after["min_asset_confidence"] == 6
            assert audit.updated_by == "alice@example.com"
        finally:
            await session.close()
            await engine.dispose()

    run(scenario())
