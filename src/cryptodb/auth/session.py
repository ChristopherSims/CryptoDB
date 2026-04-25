"""JWT session management."""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.config import settings
from cryptodb.db.metadata import Session as SessionModel, TokenBlacklist, User


def _hash_token(token: str) -> str:
    return hashlib.sha3_256(token.encode()).hexdigest()


def create_access_token(user_id: str, extra_claims: dict[str, Any] | None = None) -> str:
    """Issue a short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    claims: dict[str, Any] = {
        "sub": user_id,
        "iat": now,
        "exp": expire,
        "type": "access",
        "jti": str(uuid.uuid4()),
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
        "jti": str(uuid.uuid4()),
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


async def rotate_refresh_token(session: AsyncSession, refresh_token: str) -> tuple[str, str] | None:
    """Rotate a refresh token: validate old, revoke it, issue new pair."""
    claims = decode_token(refresh_token)
    if not claims:
        return None
    if claims.get("type") != "refresh":
        return None
    user_id = claims.get("sub")
    if not user_id:
        return None

    token_hash = _hash_token(refresh_token)
    result = await session.execute(
        select(SessionModel).where(
            SessionModel.refresh_token_hash == token_hash,
            SessionModel.revoked == False,  # noqa: E712
        )
    )
    db_session = result.scalar_one_or_none()
    if db_session is None or db_session.expires_at < datetime.now(timezone.utc):
        return None

    # Revoke old session
    db_session.revoked = True

    # Blacklist the old refresh token jti
    jti = claims.get("jti")
    if jti:
        session.add(TokenBlacklist(
            jti=jti,
            expires_at=db_session.expires_at,
        ))

    # Issue new tokens
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        return None
    access, refresh = await create_session(session, user)
    await session.flush()
    return access, refresh


async def revoke_token(session: AsyncSession, token: str) -> bool:
    """Blacklist a token by its jti claim."""
    claims = decode_token(token)
    if not claims:
        return False
    jti = claims.get("jti")
    exp = claims.get("exp")
    if not jti or not exp:
        return False
    expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
    session.add(TokenBlacklist(jti=jti, expires_at=expires_at))
    await session.flush()
    return True


async def is_token_blacklisted(session: AsyncSession, jti: str) -> bool:
    result = await session.execute(
        select(TokenBlacklist).where(TokenBlacklist.jti == jti)
    )
    return result.scalar_one_or_none() is not None


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
