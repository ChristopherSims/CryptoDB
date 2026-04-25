"""Tests for record-level ACL module."""

import pytest
from sqlalchemy import select

from cryptodb.auth.acl import can_access, grant_access
from cryptodb.db.metadata import Record, RecordACL, User


def _make_record(owner_id: str) -> Record:
    return Record(
        owner_id=owner_id,
        blob_path="test",
        cipher_name="aes-256-gcm",
        encrypted_dek={"ciphertext": "x", "iv": "n", "algorithm": "aes-256-gcm-wrap"},
        integrity_token={"hmac": "abc", "salt": "def"},
    )


class TestGrantAccess:
    async def test_grant_to_user(self, db_session, admin_user):
        record = _make_record(admin_user.id)
        db_session.add(record)
        await db_session.flush()
        acl = await grant_access(db_session, record, admin_user, "read", user=admin_user)
        assert acl.record_id == record.id
        assert acl.user_id == admin_user.id
        assert acl.permission == "read"
        assert acl.granted_by == admin_user.id

    async def test_grant_to_role(self, db_session, admin_user):
        record = _make_record(admin_user.id)
        db_session.add(record)
        await db_session.flush()
        acl = await grant_access(db_session, record, admin_user, "write", role="reader")
        assert acl.record_id == record.id
        assert acl.role == "reader"
        assert acl.user_id is None


class TestCanAccess:
    async def test_owner_always_access(self, db_session, admin_user):
        record = _make_record(admin_user.id)
        db_session.add(record)
        await db_session.flush()
        assert await can_access(db_session, admin_user, record, "read") is True

    async def test_no_acl_denies(self, db_session, admin_user):
        other = User(username="other", password_hash="x", role="reader")
        db_session.add(other)
        await db_session.flush()
        record = _make_record(admin_user.id)
        db_session.add(record)
        await db_session.flush()
        assert await can_access(db_session, other, record, "read") is False

    async def test_explicit_acl_allows(self, db_session, admin_user):
        other = User(username="other", password_hash="x", role="reader")
        db_session.add(other)
        await db_session.flush()
        record = _make_record(admin_user.id)
        db_session.add(record)
        await db_session.flush()
        await grant_access(db_session, record, admin_user, "read", user=other)
        await db_session.commit()
        assert await can_access(db_session, other, record, "read") is True

    async def test_wrong_permission_denies(self, db_session, admin_user):
        other = User(username="other", password_hash="x", role="reader")
        db_session.add(other)
        await db_session.flush()
        record = _make_record(admin_user.id)
        db_session.add(record)
        await db_session.flush()
        await grant_access(db_session, record, admin_user, "read", user=other)
        await db_session.commit()
        assert await can_access(db_session, other, record, "delete") is False

    async def test_role_based_acl(self, db_session, admin_user):
        other = User(username="other", password_hash="x", role="editor")
        db_session.add(other)
        await db_session.flush()
        record = _make_record(admin_user.id)
        db_session.add(record)
        await db_session.flush()
        await grant_access(db_session, record, admin_user, "read", role="editor")
        await db_session.commit()
        assert await can_access(db_session, other, record, "read") is True
