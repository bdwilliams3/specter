from fastapi import APIRouter, HTTPException, Depends
from app.integrations import splunk, cribl, grafana
from app.auth.dependencies import get_current_user

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


@router.post("/{integration}/test")
async def test_integration(integration: str, _user: dict = Depends(get_current_user)):
    if integration == "splunk":
        return await splunk.test_connection()
    elif integration == "cribl":
        return await cribl.test_connection()
    elif integration == "grafana":
        return await grafana.test_connection()
    else:
        raise HTTPException(status_code=404, detail=f"Unknown integration '{integration}'")
