import httpx
import logging
from jose import jwt, JWTError
from app.config import settings

logger = logging.getLogger(__name__)

_oidc_config: dict | None = None
_jwks: dict | None = None


async def get_oidc_config() -> dict:
    global _oidc_config
    if _oidc_config:
        return _oidc_config
    url = f"{settings.oidc_issuer.rstrip('/')}/.well-known/openid-configuration"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=10)
        resp.raise_for_status()
        _oidc_config = resp.json()
    return _oidc_config


async def get_jwks() -> dict:
    global _jwks
    if _jwks:
        return _jwks
    config = await get_oidc_config()
    async with httpx.AsyncClient() as client:
        resp = await client.get(config["jwks_uri"], timeout=10)
        resp.raise_for_status()
        _jwks = resp.json()
    return _jwks


async def get_authorization_url(state: str) -> str:
    config = await get_oidc_config()
    scopes = settings.oidc_scopes.replace(",", " ")
    params = (
        f"response_type=code"
        f"&client_id={settings.oidc_client_id}"
        f"&redirect_uri={settings.oidc_redirect_uri}"
        f"&scope={scopes}"
        f"&state={state}"
    )
    return f"{config['authorization_endpoint']}?{params}"


async def exchange_code(code: str) -> dict:
    config = await get_oidc_config()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            config["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.oidc_redirect_uri,
                "client_id": settings.oidc_client_id,
                "client_secret": settings.oidc_client_secret,
            },
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()


async def validate_token(token: str) -> dict:
    jwks = await get_jwks()
    try:
        payload = jwt.decode(
            token,
            jwks,
            algorithms=["RS256", "ES256"],
            audience=settings.oidc_client_id,
            options={"verify_exp": True},
        )
        return payload
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}")
