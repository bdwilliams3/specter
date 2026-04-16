import secrets
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import RedirectResponse, JSONResponse
from app.auth.oidc import get_authorization_url, exchange_code, validate_token
from app.auth.dependencies import get_current_user
from app.config import settings
from fastapi import Depends

router = APIRouter(prefix="/auth", tags=["auth"])

_state_store: set[str] = set()


@router.get("/login")
async def login():
    if not settings.oidc_enabled:
        return JSONResponse({"message": "OIDC not configured — running in dev mode", "dev": True})
    state = secrets.token_urlsafe(32)
    _state_store.add(state)
    url = await get_authorization_url(state)
    return RedirectResponse(url)


@router.get("/callback")
async def callback(code: str = Query(...), state: str = Query(...)):
    if state not in _state_store:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    _state_store.discard(state)
    tokens = await exchange_code(code)
    # Return access token as JSON; frontend stores in memory/session
    return JSONResponse({
        "access_token": tokens.get("access_token"),
        "id_token": tokens.get("id_token"),
        "token_type": "bearer",
        "expires_in": tokens.get("expires_in"),
    })


@router.get("/me")
async def me(user: dict = Depends(get_current_user)):
    return {
        "sub": user.get("sub"),
        "email": user.get("email"),
        "name": user.get("name"),
    }
