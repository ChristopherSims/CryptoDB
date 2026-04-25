"""Tests for JWT session management."""

import time
from datetime import datetime, timedelta, timezone

import pytest

from cryptodb.auth.session import (
    create_access_token,
    create_refresh_token,
    decode_token,
    is_token_blacklisted,
    revoke_token,
    rotate_refresh_token,
)
from cryptodb.config import settings


class TestCreateAccessToken:
    def test_contains_expected_claims(self):
        token = create_access_token("user-123")
        claims = decode_token(token)
        assert claims is not None
        assert claims["sub"] == "user-123"
        assert claims["type"] == "access"
        assert "jti" in claims
        assert "exp" in claims

    def test_extra_claims_merged(self):
        token = create_access_token("user-123", {"role": "admin"})
        claims = decode_token(token)
        assert claims["role"] == "admin"

    def test_expires_in_future(self):
        token = create_access_token("user-123")
        claims = decode_token(token)
        exp = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
        assert exp > datetime.now(timezone.utc)


class TestCreateRefreshToken:
    def test_contains_expected_claims(self):
        token = create_refresh_token("user-123")
        claims = decode_token(token)
        assert claims["type"] == "refresh"
        assert claims["sub"] == "user-123"
        assert "jti" in claims


class TestDecodeToken:
    def test_invalid_token_returns_none(self):
        assert decode_token("totally.invalid.token") is None

    def test_tampered_token_returns_none(self):
        token = create_access_token("user-123")
        assert decode_token(token + "x") is None


class TestRevokeToken:
    async def test_revoke_adds_to_blacklist(self, db_session):
        token = create_access_token("user-123")
        ok = await revoke_token(db_session, token)
        assert ok is True
        claims = decode_token(token)
        assert claims is not None
        assert await is_token_blacklisted(db_session, claims["jti"]) is True

    async def test_revoke_invalid_token_returns_false(self, db_session):
        ok = await revoke_token(db_session, "bad.token")
        assert ok is False

    async def test_not_blacklisted_returns_false(self, db_session):
        token = create_access_token("user-123")
        claims = decode_token(token)
        assert await is_token_blacklisted(db_session, claims["jti"]) is False


class TestRotateRefreshToken:
    async def test_rotation_issues_new_pair(self, db_session, admin_user):
        from cryptodb.auth.session import create_session
        access, refresh = await create_session(db_session, admin_user)
        await db_session.commit()
        result = await rotate_refresh_token(db_session, refresh)
        assert result is not None
        new_access, new_refresh = result
        assert new_access != access
        assert new_refresh != refresh

    async def test_old_refresh_revoked(self, db_session, admin_user):
        from cryptodb.auth.session import create_session
        access, refresh = await create_session(db_session, admin_user)
        await db_session.commit()
        result = await rotate_refresh_token(db_session, refresh)
        assert result is not None
        # Second use of same refresh should fail
        result2 = await rotate_refresh_token(db_session, refresh)
        assert result2 is None

    async def test_invalid_refresh_returns_none(self, db_session):
        result = await rotate_refresh_token(db_session, "invalid.token")
        assert result is None

    async def test_expired_refresh_returns_none(self, db_session, admin_user):
        from cryptodb.auth.session import create_refresh_token, _hash_token
        from cryptodb.db.metadata import Session as SessionModel
        refresh = create_refresh_token(admin_user.id)
        # Manually create expired session
        expired = datetime.now(timezone.utc) - timedelta(days=1)
        db_session.add(SessionModel(
            user_id=admin_user.id,
            refresh_token_hash=_hash_token(refresh),
            expires_at=expired,
        ))
        await db_session.commit()
        result = await rotate_refresh_token(db_session, refresh)
        assert result is None
