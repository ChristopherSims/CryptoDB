"""FastAPI dependency injection helpers."""

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.api.rate_limit import check_rate_limit, get_rate_limit_for_endpoint
from cryptodb.auth.geo import is_allowed
from cryptodb.auth.session import decode_token, get_user_from_token, is_token_blacklisted
from cryptodb.config import settings
from cryptodb.db.connection import get_session
from cryptodb.db.metadata import User

security = HTTPBearer()


async def get_db():
    async for session in get_session():
        yield session


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return ""


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> User:
    # Rate limiting by endpoint + rough client IP
    endpoint = request.url.path
    limit, window = get_rate_limit_for_endpoint(endpoint)
    client_ip = _get_client_ip(request)
    rate_key = f"{client_ip}:{endpoint}"
    if not check_rate_limit(rate_key, limit, window):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
        )

    # Geofencing
    geo_rule = settings.get_geo_rule()
    if geo_rule and not is_allowed(client_ip, geo_rule):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Request blocked by geofencing policy",
        )

    token = credentials.credentials
    claims = decode_token(token)
    if claims is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

    # Blacklist check
    jti = claims.get("jti")
    if jti and await is_token_blacklisted(session, jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
        )

    user = await get_user_from_token(session, token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

    # Attach request_id to user for downstream use (monkey-patch safely)
    request.state.user = user
    request.state.request_id = request.headers.get("x-request-id", "")
    return user
