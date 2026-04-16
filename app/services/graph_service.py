import math
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.asset import AIAsset
from app.models.connection import AssetConnection

PROVIDER_COLORS = {
    "k8s": "#3b82f6",
    "aws": "#f97316",
    "gcp": "#10b981",
    "azure": "#8b5cf6",
    "ibm": "#06b6d4",
    "alibaba": "#ef4444",
}


async def build_graph(db: AsyncSession, asset_id: str | None = None) -> dict:
    if asset_id:
        asset_result = await db.execute(select(AIAsset).where(AIAsset.id == asset_id))
        center = asset_result.scalar_one_or_none()
        if not center:
            return {"nodes": [], "edges": []}
        conn_result = await db.execute(
            select(AssetConnection).where(
                (AssetConnection.source_id == asset_id) | (AssetConnection.target_id == asset_id)
            )
        )
        connections = conn_result.scalars().all()
        neighbor_ids = {c.source_id for c in connections} | {c.target_id for c in connections}
        neighbor_result = await db.execute(select(AIAsset).where(AIAsset.id.in_(neighbor_ids)))
        assets = [center] + list(neighbor_result.scalars().all())
    else:
        asset_result = await db.execute(select(AIAsset))
        assets = list(asset_result.scalars().all())
        conn_result = await db.execute(select(AssetConnection))
        connections = list(conn_result.scalars().all())

    nodes = []
    for i, asset in enumerate(assets):
        angle = (2 * math.pi * i) / max(len(assets), 1)
        radius = 300
        nodes.append({
            "id": asset.id,
            "type": "assetNode",
            "position": {"x": radius * round(math.cos(angle), 4),
                         "y": radius * round(math.sin(angle), 4)},
            "data": {
                "label": asset.name,
                "asset_type": asset.asset_type,
                "provider": asset.provider,
                "risk_score": asset.risk_score,
                "color": PROVIDER_COLORS.get(asset.provider, "#6b7280"),
                "namespace": asset.namespace,
            }
        })

    edges = []
    for conn in connections:
        edges.append({
            "id": conn.id,
            "source": conn.source_id,
            "target": conn.target_id,
            "label": conn.label or conn.relation_type,
            "data": {"relation_type": conn.relation_type, "trust_level": conn.trust_level},
            "animated": conn.relation_type in ("data_flow", "api_call"),
        })

    return {"nodes": nodes, "edges": edges}
