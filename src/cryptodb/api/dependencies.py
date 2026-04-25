"""FastAPI dependency injection helpers."""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.auth.session import decode_token, get_user_from_token
from cryptodb.db.connection import get_session
from cryptodb.db.metadata import User

security = HTTPBearer()


async def get_db():
    async for session in get_session():
        yield session


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> User:
    token = credentials.credentials
    user = await get_user_from_token(session, token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )
    return user
