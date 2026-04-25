"""JWT session management."""

from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.config import settings
from cryptodb.db.metadata import Session as SessionModel, User


def create_access_token(user_id: str, extra_claims: dict[str, Any] | None = None) -> str:
    """Issue a short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    claims: dict[str, Any] = {
        "sub": user_id,
        "iat": now,
        "exp": expire,
        "type": "access",
    }
    if extra_claims:
        claims.update(extra_claims)
    return jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_refresh_token(user_id: str) -> str:
    """Issue a longer-lived JWT refresh token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.jwt_refresh_token_expire_days)
    claims = {
        "sub": user_id,
        "iat": now,
        "exp": expire,
        "type": "refresh",
    }
    return jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any] | None:
    """Decode and validate a JWT. Returns None on failure."""
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None


async def create_session(session: AsyncSession, user: User) -> tuple[str, str]:
    """Create DB session and return (access_token, refresh_token)."""
    access = create_access_token(user.id, {"role": user.role})
    refresh = create_refresh_token(user.id)
    db_session = SessionModel(
        user_id=user.id,
        refresh_token_hash=_hash_token(refresh),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_token_expire_days),
    )
    session.add(db_session)
    await session.flush()
    return access, refresh


def _hash_token(token: str) -> str:
    import hashlib

    return hashlib.sha3_256(token.encode()).hexdigest()


async def get_user_from_token(db_session: AsyncSession, token: str) -> User | None:
    """Resolve a JWT access token to a User."""
    claims = decode_token(token)
    if not claims:
        return None
    if claims.get("type") != "access":
        return None
    user_id = claims.get("sub")
    if not user_id:
        return None
    result = await db_session.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()
