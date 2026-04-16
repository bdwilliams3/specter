from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.asset import AIAsset, AssetType

PROVIDER_COLORS = {
    "k8s":      "#3b82f6",
    "aws":      "#f97316",
    "gcp":      "#10b981",
    "azure":    "#8b5cf6",
    "ibm":      "#06b6d4",
    "alibaba":  "#ef4444",
}

# Vertical tier within a provider group
_TYPE_TIER = {
    AssetType.k8s_deployment:   0,
    AssetType.mcp_server:       1,
    AssetType.agentic_framework:1,
    AssetType.model_server:     1,
    AssetType.k8s_service:      2,
    AssetType.llm_api_endpoint: 0,
    AssetType.cloud_ai_service: 0,
    AssetType.saas_ai_tool:     0,
    AssetType.unknown:          1,
}

_NODE_W   = 220   # card width
_NODE_H   = 110   # card height
_GAP_X    = 60    # horizontal gap between cards
_GAP_Y    = 80    # vertical gap between tiers
_GROUP_GAP = 160  # gap between provider groups


def _layout(assets: list[AIAsset]) -> dict[str, tuple[float, float]]:
    """Assign (x, y) positions grouped by provider, tiered by asset type."""
    # Gather unique providers preserving insertion order
    seen: dict[str, list[AIAsset]] = {}
    for a in assets:
        seen.setdefault(a.provider, []).append(a)

    positions: dict[str, tuple[float, float]] = {}
    cursor_x = 0.0

    for provider, group in seen.items():
        # Sort by tier then by name for stable layout
        group.sort(key=lambda a: (_TYPE_TIER.get(a.asset_type, 1), a.name))

        # How many tiers does this group have?
        tiers: dict[int, list[AIAsset]] = {}
        for a in group:
            t = _TYPE_TIER.get(a.asset_type, 1)
            tiers.setdefault(t, []).append(a)

        # Width of this group = widest tier * card width + gaps
        max_in_row = max(len(v) for v in tiers.values()) if tiers else 1
        group_w = max_in_row * (_NODE_W + _GAP_X) - _GAP_X

        # Position each card
        for tier_idx, tier_assets in sorted(tiers.items()):
            row_w = len(tier_assets) * (_NODE_W + _GAP_X) - _GAP_X
            row_start_x = cursor_x + (group_w - row_w) / 2  # center the row
            y = tier_idx * (_NODE_H + _GAP_Y)
            for col, a in enumerate(tier_assets):
                x = row_start_x + col * (_NODE_W + _GAP_X)
                positions[a.id] = (round(x, 1), round(y, 1))

        cursor_x += group_w + _GROUP_GAP

    return positions


def _infer_edges(assets: list[AIAsset]) -> list[dict]:
    """Derive edges from asset metadata without needing AssetConnection rows."""
    edges: list[dict] = []
    seen_pairs: set[tuple[str, str]] = set()

    def add_edge(src: str, tgt: str, label: str, animated: bool = False) -> None:
        pair = (src, tgt)
        if pair in seen_pairs:
            return
        seen_pairs.add(pair)
        edges.append({
            "id": f"{src[:8]}-{tgt[:8]}",
            "source": src,
            "target": tgt,
            "label": label,
            "animated": animated,
            "style": {"strokeWidth": 1.5},
            "labelStyle": {"fontSize": 10, "fill": "#64748b"},
            "labelBgStyle": {"fill": "#0f1117", "fillOpacity": 0.8},
        })

    # ── K8s edges ──────────────────────────────────────────────────────────────
    k8s = [a for a in assets if a.provider == "k8s"]

    deployments    = [a for a in k8s if a.asset_type == AssetType.k8s_deployment]
    pods           = [a for a in k8s if a.asset_type in (AssetType.mcp_server, AssetType.agentic_framework, AssetType.model_server)]
    services       = [a for a in k8s if a.asset_type == AssetType.k8s_service]
    agents         = [a for a in pods if a.asset_type == AssetType.agentic_framework]
    mcp_pods       = [a for a in pods if a.asset_type == AssetType.mcp_server]

    # Deployment → Pod  (pod name starts with deployment name + "-")
    for dep in deployments:
        for pod in pods:
            if pod.name.startswith(dep.name + "-") and pod.namespace == dep.namespace:
                add_edge(dep.id, pod.id, "manages")

    # Service → Pod  (service name is prefix of pod name)
    for svc in services:
        for pod in pods:
            if pod.name.startswith(svc.name + "-") and pod.namespace == svc.namespace:
                add_edge(svc.id, pod.id, "routes to", animated=True)

    # Agent → MCP service  (agent in same namespace calls the MCP service)
    for agent in agents:
        for svc in services:
            if agent.namespace == svc.namespace:
                add_edge(agent.id, svc.id, "calls MCP", animated=True)
        # Also direct pod-to-pod if no service present
        if not services:
            for mcp in mcp_pods:
                if agent.namespace == mcp.namespace:
                    add_edge(agent.id, mcp.id, "calls MCP", animated=True)

    # ── Azure edges ────────────────────────────────────────────────────────────
    azure = [a for a in assets if a.provider == "azure"]

    # Assets in the same resource group are co-located
    rg_groups: dict[str, list[AIAsset]] = {}
    for a in azure:
        rg = (a.metadata_ or {}).get("resource_group", "")
        if rg:
            rg_groups.setdefault(rg, []).append(a)

    for rg, group in rg_groups.items():
        if len(group) < 2:
            continue
        # Connect OpenAI/LLM endpoints to other AI services in same RG
        endpoints = [a for a in group if a.asset_type == AssetType.llm_api_endpoint]
        others    = [a for a in group if a.asset_type != AssetType.llm_api_endpoint]
        for ep in endpoints:
            for other in others:
                add_edge(ep.id, other.id, "same resource group")

    return edges


async def build_graph(db: AsyncSession, asset_id: str | None = None) -> dict:
    if asset_id:
        result = await db.execute(select(AIAsset).where(AIAsset.id == asset_id))
        center = result.scalar_one_or_none()
        if not center:
            return {"nodes": [], "edges": []}
        assets = [center]
    else:
        result = await db.execute(select(AIAsset))
        assets = list(result.scalars().all())

    positions = _layout(assets)

    nodes = []
    for a in assets:
        x, y = positions.get(a.id, (0, 0))
        nodes.append({
            "id": a.id,
            "type": "assetNode",
            "position": {"x": x, "y": y},
            "data": {
                "label":      a.name,
                "asset_type": a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type),
                "provider":   a.provider,
                "risk_score": a.risk_score,
                "color":      PROVIDER_COLORS.get(a.provider, "#6b7280"),
                "namespace":  a.namespace,
                "cluster":    a.cluster,
            },
        })

    edges = _infer_edges(assets)

    return {"nodes": nodes, "edges": edges}
