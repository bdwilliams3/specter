from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user
from app.database import get_db
from app.detectors.registry import RULES
from app.models.rule_config import RuleConfig
from app.schemas.rule_config import RuleConfigBulkPatch, RuleConfigOut, RuleConfigPatch
from app.services.rule_config import patch_rule_config, seed_rule_defaults


router = APIRouter(prefix="/api/rules", tags=["rules"])


def _actor(user: dict) -> str:
    return user.get("email") or user.get("sub") or "unknown"


def _known_rule_ids() -> set[str]:
    return {rule["rule_id"] for rule in RULES}


@router.get("", response_model=dict)
async def list_rule_configs(
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(get_current_user),
):
    await seed_rule_defaults(db)
    configs = [await db.get(RuleConfig, rule["rule_id"]) for rule in RULES]
    return {
        "total": len(configs),
        "items": [RuleConfigOut.model_validate(config).model_dump() for config in configs if config],
    }


@router.patch("/{rule_id}", response_model=RuleConfigOut)
async def update_rule_config(
    rule_id: str,
    patch: RuleConfigPatch,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    if rule_id not in _known_rule_ids():
        raise HTTPException(status_code=404, detail="Rule not found")
    payload = patch.model_dump(exclude_unset=True)
    config = await patch_rule_config(db, rule_id, payload, _actor(user))
    return RuleConfigOut.model_validate(config)


@router.patch("", response_model=dict)
async def bulk_update_rule_configs(
    updates: list[RuleConfigBulkPatch],
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    known = _known_rule_ids()
    unknown = [item.rule_id for item in updates if item.rule_id not in known]
    if unknown:
        raise HTTPException(status_code=404, detail={"unknown_rule_ids": unknown})

    actor = _actor(user)
    configs = []
    for item in updates:
        payload = item.patch.model_dump(exclude_unset=True)
        configs.append(await patch_rule_config(db, item.rule_id, payload, actor))

    return {
        "total": len(configs),
        "items": [RuleConfigOut.model_validate(config).model_dump() for config in configs],
    }
