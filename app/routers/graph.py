from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.services.graph_service import build_graph
from app.auth.dependencies import get_current_user
from typing import Optional

router = APIRouter(prefix="/api/graph", tags=["graph"])


@router.get("")
async def get_graph(
    asset_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(get_current_user),
):
    return await build_graph(db, asset_id=asset_id)
