from pathlib import Path
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.rule_config import RuleConfig, RuleConfigAudit


DEFAULTS_PATH = Path(__file__).resolve().parents[1] / "detectors" / "rule_defaults.yaml"
PATCHABLE_FIELDS = {"min_asset_confidence", "enabled", "severity_override", "route"}


def load_rule_defaults(path: Path = DEFAULTS_PATH) -> list[dict]:
    defaults: list[dict] = []
    current: dict | None = None
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line == "rules:":
            continue
        if line.startswith("- "):
            if current:
                defaults.append(current)
            current = {}
            line = line[2:].strip()
        if ":" not in line or current is None:
            continue
        key, raw_value = line.split(":", 1)
        value = raw_value.strip()
        if value.lower() in {"true", "false"}:
            parsed: str | bool | int | None = value.lower() == "true"
        elif value.lower() in {"null", "none"}:
            parsed = None
        else:
            try:
                parsed = int(value)
            except ValueError:
                parsed = value.strip("\"'")
        current[key.strip()] = parsed
    if current:
        defaults.append(current)
    return defaults


async def seed_rule_defaults(db: AsyncSession) -> None:
    for default in load_rule_defaults():
        rule_id = str(default["rule_id"])
        existing = await db.get(RuleConfig, rule_id)
        if existing:
            continue
        db.add(
            RuleConfig(
                rule_id=rule_id,
                min_asset_confidence=int(default.get("min_asset_confidence", 0)),
                enabled=bool(default.get("enabled", True)),
            )
        )
    await db.commit()


async def get_rule_config_map(db: AsyncSession) -> dict[str, RuleConfig]:
    result = await db.execute(select(RuleConfig))
    return {config.rule_id: config for config in result.scalars().all()}


def rule_config_snapshot(config: RuleConfig) -> dict:
    return {
        "rule_id": config.rule_id,
        "min_asset_confidence": config.min_asset_confidence,
        "enabled": config.enabled,
        "severity_override": config.severity_override,
        "route": config.route,
        "updated_by": config.updated_by,
        "updated_at": config.updated_at.isoformat() if config.updated_at else None,
    }


async def patch_rule_config(db: AsyncSession, rule_id: str, patch: dict, updated_by: str) -> RuleConfig:
    config = await db.get(RuleConfig, rule_id)
    if not config:
        config = RuleConfig(rule_id=rule_id)
        db.add(config)
        await db.flush()

    before = rule_config_snapshot(config)
    for field, value in patch.items():
        if field not in PATCHABLE_FIELDS:
            continue
        setattr(config, field, value)
    config.updated_by = updated_by
    config.updated_at = datetime.utcnow()
    after = rule_config_snapshot(config)

    db.add(
        RuleConfigAudit(
            rule_id=rule_id,
            updated_by=updated_by,
            before=before,
            after=after,
        )
    )
    await db.commit()
    await db.refresh(config)
    return config
