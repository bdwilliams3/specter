from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.services.report_service import export_assets, export_threats, export_vulns
from app.auth.dependencies import get_current_user

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/export")
async def export_report(
    format: str = Query("json", regex="^(csv|html|json)$"),
    entity: str = Query("assets", regex="^(assets|threats|vulnerabilities)$"),
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(get_current_user),
):
    if entity == "assets":
        content, media_type, filename = await export_assets(db, format)
    elif entity == "threats":
        content, media_type, filename = await export_threats(db, format)
    else:
        content, media_type, filename = await export_vulns(db, format)

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
