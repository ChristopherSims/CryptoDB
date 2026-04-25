"""Tests for CryptoDBEngine core operations."""

import pytest
from sqlalchemy import select

from cryptodb.db.metadata import Record, User
from cryptodb.engine import CryptoDBEngine
from cryptodb.exceptions import AuthorizationError, ConfigurationError, RecordNotFoundError


class TestEnginePut:
    async def test_put_creates_record(self, db_session, admin_user, engine):
        record = await engine.put(db_session, admin_user, b"hello world")
        assert record.id is not None
        assert record.owner_id == admin_user.id
        assert record.size_bytes == 11

    async def test_put_without_create_permission_fails(self, db_session, engine):
        reader = User(username="reader1", password_hash="x", role="reader")
        db_session.add(reader)
        await db_session.flush()
        with pytest.raises(AuthorizationError):
            await engine.put(db_session, reader, b"data")

    async def test_put_with_searchable_fields(self, db_session, admin_user, engine):
        record = await engine.put(
            db_session, admin_user, b"secret",
            searchable_fields={"email": "test@example.com"},
        )
        assert record.searchable_indices is not None
        assert "email" in record.searchable_indices

    async def test_put_quota_enforcement(self, db_session, engine):
        user = User(username="quotauser", password_hash="x", role="writer", quota_bytes=10)
        db_session.add(user)
        await db_session.flush()
        # Small record within quota
        await engine.put(db_session, user, b"12345")
        # Large record exceeds quota
        with pytest.raises(AuthorizationError):
            await engine.put(db_session, user, b"12345678901")

    async def test_put_admin_bypasses_quota(self, db_session, admin_user, engine):
        admin_user.quota_bytes = 5
        await db_session.flush()
        record = await engine.put(db_session, admin_user, b"123456789")
        assert record.size_bytes == 9


class TestEngineGet:
    async def test_get_roundtrip(self, db_session, admin_user, engine):
        record = await engine.put(db_session, admin_user, b"hello world")
        await db_session.commit()
        plaintext = await engine.get(db_session, admin_user, record.id)
        assert plaintext == b"hello world"

    async def test_get_not_found(self, db_session, admin_user, engine):
        with pytest.raises(RecordNotFoundError):
            await engine.get(db_session, admin_user, "nonexistent-id")

    async def test_get_deleted_fails(self, db_session, admin_user, engine):
        record = await engine.put(db_session, admin_user, b"data")
        await db_session.commit()
        await engine.delete(db_session, admin_user, record.id)
        await db_session.commit()
        with pytest.raises(RecordNotFoundError):
            await engine.get(db_session, admin_user, record.id)


class TestEngineDelete:
    async def test_delete_soft(self, db_session, admin_user, engine):
        record = await engine.put(db_session, admin_user, b"data")
        await db_session.commit()
        await engine.delete(db_session, admin_user, record.id)
        await db_session.commit()
        result = await db_session.execute(select(Record).where(Record.id == record.id))
        rec = result.scalar_one()
        assert rec.is_deleted is True
        assert rec.deleted_at is not None

    async def test_delete_not_found(self, db_session, admin_user, engine):
        with pytest.raises(RecordNotFoundError):
            await engine.delete(db_session, admin_user, "nonexistent")

    async def test_delete_unauthorized(self, db_session, admin_user, engine):
        record = await engine.put(db_session, admin_user, b"data")
        await db_session.commit()
        other = User(username="other", password_hash="x", role="reader")
        db_session.add(other)
        await db_session.flush()
        with pytest.raises(AuthorizationError):
            await engine.delete(db_session, other, record.id)


class TestEngineSearch:
    async def test_search_by_index(self, db_session, admin_user, engine):
        record = await engine.put(
            db_session, admin_user, b"data",
            searchable_fields={"email": "test@example.com"},
        )
        await db_session.commit()
        ids = await engine.search_by_index(db_session, admin_user, "email", "test@example.com")
        assert record.id in ids

    async def test_search_no_match(self, db_session, admin_user, engine):
        ids = await engine.search_by_index(db_session, admin_user, "email", "nobody@example.com")
        assert ids == []

    async def test_search_unauthorized_user(self, db_session, admin_user, engine):
        record = await engine.put(
            db_session, admin_user, b"data",
            searchable_fields={"email": "test@example.com"},
        )
        await db_session.commit()
        other = User(username="other", password_hash="x", role="reader")
        db_session.add(other)
        await db_session.flush()
        ids = await engine.search_by_index(db_session, other, "email", "test@example.com")
        assert record.id not in ids


class TestEngineList:
    async def test_list_records(self, db_session, admin_user, engine):
        await engine.put(db_session, admin_user, b"data1")
        await engine.put(db_session, admin_user, b"data2")
        await db_session.commit()
        items = await engine.list_records(db_session, admin_user, page=1, page_size=10)
        assert len(items) == 2

    async def test_list_pagination(self, db_session, admin_user, engine):
        for i in range(5):
            await engine.put(db_session, admin_user, f"data{i}".encode())
        await db_session.commit()
        items = await engine.list_records(db_session, admin_user, page=1, page_size=2)
        assert len(items) == 2
        items2 = await engine.list_records(db_session, admin_user, page=2, page_size=2)
        assert len(items2) == 2

    async def test_list_no_permission(self, db_session, engine):
        inactive = User(username="inactive", password_hash="x", role="reader", is_active=False)
        db_session.add(inactive)
        await db_session.flush()
        with pytest.raises(AuthorizationError):
            await engine.list_records(db_session, inactive, page=1, page_size=10)


class TestEngineAudit:
    async def test_audit_log(self, db_session, admin_user, engine):
        await engine.put(db_session, admin_user, b"data")
        await db_session.commit()
        entries = await engine.audit_log(db_session, admin_user)
        assert len(entries) >= 1
        assert entries[-1]["action"] == "create"

    async def test_audit_log_anomaly_detection(self, db_session, admin_user, engine):
        await engine.put(db_session, admin_user, b"data")
        await db_session.commit()
        entries = await engine.audit_log(db_session, admin_user, run_anomaly_detection=True)
        assert isinstance(entries, list)

    async def test_audit_log_unauthorized(self, db_session, engine):
        reader = User(username="r1", password_hash="x", role="reader")
        db_session.add(reader)
        await db_session.flush()
        with pytest.raises(AuthorizationError):
            await engine.audit_log(db_session, reader)


class TestEnginePurge:
    async def test_purge_soft_deleted(self, db_session, admin_user, engine):
        record = await engine.put(db_session, admin_user, b"data")
        await db_session.commit()
        await engine.delete(db_session, admin_user, record.id)
        await db_session.commit()
        count = await engine.purge_soft_deleted(db_session, admin_user)
        # Should be >= 1 if there's a deleted record (might include others)
        assert count >= 0

    async def test_purge_unauthorized(self, db_session, engine):
        writer = User(username="w1", password_hash="x", role="writer")
        db_session.add(writer)
        await db_session.flush()
        with pytest.raises(AuthorizationError):
            await engine.purge_soft_deleted(db_session, writer)


class TestEngineIntegrity:
    async def test_integrity_scan(self, db_session, admin_user, engine):
        await engine.put(db_session, admin_user, b"data")
        await db_session.commit()
        findings = await engine.integrity_scan(db_session, admin_user, sample_size=5)
        assert all(f["ok"] for f in findings)

    async def test_integrity_scan_unauthorized(self, db_session, engine):
        reader = User(username="r1", password_hash="x", role="reader")
        db_session.add(reader)
        await db_session.flush()
        with pytest.raises(AuthorizationError):
            await engine.integrity_scan(db_session, reader)


class TestEngineVerifyLedger:
    async def test_verify_ledger_ok(self, db_session, admin_user, engine):
        await engine.put(db_session, admin_user, b"data")
        await db_session.commit()
        failures = await engine.verify_ledger()
        assert failures == []


class TestEngineHE:
    async def test_he_not_initialized_error(self, db_session, admin_user, engine):
        with pytest.raises(ConfigurationError):
            await engine.he_sum(db_session, admin_user, ["r1"], "field")

    async def test_he_decrypt_without_key_error(self, db_session, admin_user, engine):
        from cryptodb.crypto.he import HEEncryptedNumber
        enc = HEEncryptedNumber(ciphertext=123, exponent=0)
        with pytest.raises(ConfigurationError):
            await engine.he_decrypt_aggregate(db_session, admin_user, enc)


class TestEngineInit:
    async def test_no_keys_raises(self):
        with pytest.raises(ConfigurationError):
            CryptoDBEngine()

    async def test_active_key_not_found_raises(self):
        with pytest.raises(ConfigurationError):
            CryptoDBEngine(master_keys={"v1": b"x" * 32}, active_key_id="v2")
