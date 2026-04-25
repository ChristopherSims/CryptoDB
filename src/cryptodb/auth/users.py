"""User management and password hashing."""

import uuid

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.db.metadata import User

_ph = PasswordHasher()


class AuthError(Exception):
    """Base auth exception."""


def hash_password(plain: str) -> str:
    return _ph.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        _ph.verify(hashed, plain)
        return True
    except VerifyMismatchError:
        return False


async def create_user(
    session: AsyncSession,
    username: str,
    password: str,
    role: str = "reader",
    email: str | None = None,
) -> User:
    user = User(
        id=str(uuid.uuid4()),
        username=username,
        password_hash=hash_password(password),
        role=role,
        email=email,
    )
    session.add(user)
    await session.flush()
    return user


async def authenticate_user(session: AsyncSession, username: str, password: str) -> User | None:
    result = await session.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user is None:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user
