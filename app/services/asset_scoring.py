from datetime import datetime
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import AIAsset
from app.models.asset_signal import AIAssetSignal


TIER4_SIGNAL_TYPES = {
    "weak_name_match",
    "weak_label_match",
    "weak_annotation_match",
    "weak_image_match",
}

PROVIDER_ENDPOINT_SIGNAL_TYPES = {
    "ai_provider_dns",
    "ai_provider_sni",
    "ai_provider_endpoint",
}

AI_PROVIDER_HOSTS = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "google-gemini",
    "api.cohere.ai": "cohere",
    "inference.ai.azure.com": "azure-openai",
}


def normalize_signals(signals: list[dict]) -> list[dict]:
    normalized: list[dict] = []
    provider_seen: set[tuple[str, str]] = set()
    for signal in signals:
        item = dict(signal)
        if item.get("signal_type") in PROVIDER_ENDPOINT_SIGNAL_TYPES:
            host = str(item.get("value", "")).lower()
            provider = AI_PROVIDER_HOSTS.get(host, host)
            key = ("ai_provider_endpoint", provider)
            if key in provider_seen:
                continue
            provider_seen.add(key)
            item["signal_type"] = "ai_provider_endpoint"
            item["value"] = provider
            item["weight"] = max(float(item.get("weight", 5.0)), 5.0)
        normalized.append(item)
    return normalized


def calculate_ai_confidence(signals: list[dict]) -> float:
    tier4_total = 0.0
    weighted: list[float] = []
    for signal in normalize_signals(signals):
        weight = float(signal.get("weight", 0.0))
        if signal.get("signal_type") in TIER4_SIGNAL_TYPES:
            tier4_total += weight
        else:
            weighted.append(weight)
    if tier4_total:
        weighted.append(min(tier4_total, 2.0))

    score = 0.0
    for weight in sorted(weighted, reverse=True):
        score += weight * (1 - score / 10)
    return max(0.0, min(10.0, round(score, 1)))


def confidence_bucket(score: float) -> str:
    if score < 3:
        return "Speculative"
    if score < 5:
        return "Probable"
    if score < 8:
        return "Likely"
    return "Confirmed"


async def replace_asset_signals(db: AsyncSession, asset: AIAsset, signals: list[dict],
                                source_prefix: str | None = None) -> float:
    query = delete(AIAssetSignal).where(AIAssetSignal.asset_id == asset.id)
    if source_prefix:
        query = query.where(AIAssetSignal.source.like(f"{source_prefix}%"))
    await db.execute(query)

    rows = []
    now = datetime.utcnow()
    for signal in normalize_signals(signals):
        rows.append(
            AIAssetSignal(
                asset_id=asset.id,
                signal_type=str(signal["signal_type"]),
                source=str(signal.get("source", "unknown")),
                value=str(signal.get("value", "")),
                weight=float(signal.get("weight", 0.0)),
                observed_at=signal.get("observed_at") or now,
                ttl_expires_at=signal.get("ttl_expires_at"),
            )
        )
    db.add_all(rows)
    remaining = await db.execute(select(AIAssetSignal).where(AIAssetSignal.asset_id == asset.id))
    all_signals = [_signal_to_dict(row) for row in remaining.scalars().all()]
    all_signals.extend(_signal_to_dict(row) for row in rows)
    asset.ai_confidence = calculate_ai_confidence(all_signals)
    return asset.ai_confidence


async def add_runtime_signal(db: AsyncSession, asset: AIAsset, signal: dict) -> float:
    db.add(
        AIAssetSignal(
            asset_id=asset.id,
            signal_type=str(signal["signal_type"]),
            source=str(signal.get("source", "runtime")),
            value=str(signal.get("value", "")),
            weight=float(signal.get("weight", 0.0)),
            observed_at=signal.get("observed_at") or datetime.utcnow(),
            ttl_expires_at=signal.get("ttl_expires_at"),
        )
    )
    result = await db.execute(select(AIAssetSignal).where(AIAssetSignal.asset_id == asset.id))
    signals = [_signal_to_dict(row) for row in result.scalars().all()]
    signals.append(signal)
    asset.ai_confidence = calculate_ai_confidence(signals)
    return asset.ai_confidence


def _signal_to_dict(signal: AIAssetSignal) -> dict:
    return {
        "signal_type": signal.signal_type,
        "source": signal.source,
        "value": signal.value,
        "weight": signal.weight,
        "observed_at": signal.observed_at,
        "ttl_expires_at": signal.ttl_expires_at,
    }
