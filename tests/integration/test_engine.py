"""Integration tests for the CryptoDB engine."""

import os
import tempfile

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.auth.users import create_user
from cryptodb.config import settings
from cryptodb.crypto.keystore import MasterKeyStore
from cryptodb.db.connection import get_session_local, init_db, reset_engine
from cryptodb.engine import CryptoDBEngine
from cryptodb.ledger.chain import HashChain


@pytest.fixture(autouse=True)
def temp_dirs():
    with tempfile.TemporaryDirectory() as tmpdir:
        from pathlib import Path
        settings.data_dir = Path(os.path.join(tmpdir, "data"))
        settings.blob_dir = Path(os.path.join(tmpdir, "data", "blobs"))
        settings.db_path = Path(os.path.join(tmpdir, "data", "cryptodb.db"))
        settings.keys_dir = Path(os.path.join(tmpdir, "data", "keys"))
        os.makedirs(settings.data_dir, exist_ok=True)
        os.makedirs(settings.blob_dir, exist_ok=True)
        os.makedirs(settings.keys_dir, exist_ok=True)
        reset_engine()
        yield


@pytest.fixture
async def session():
    await init_db()
    SessionLocal = get_session_local()
    async with SessionLocal() as s:
        yield s
        await s.rollback()


@pytest.fixture
async def user(session: AsyncSession):
    return await create_user(session, "testuser", "password123", role="admin")


@pytest.fixture
async def engine(session: AsyncSession):
    ks = MasterKeyStore()
    kek = ks.create_master_key("test-passphrase")
    chain = await CryptoDBEngine.load_chain(session)
    return CryptoDBEngine(kek, hash_chain=chain)


class TestPutGetDelete:
    async def test_put_get(self, session: AsyncSession, user, engine: CryptoDBEngine) -> None:
        plaintext = b"my secret document"
        record = await engine.put(session, user, plaintext)
        await session.commit()

        retrieved = await engine.get(session, user, record.id)
        assert retrieved == plaintext

    async def test_delete_soft(self, session: AsyncSession, user, engine: CryptoDBEngine) -> None:
        plaintext = b"to be deleted"
        record = await engine.put(session, user, plaintext)
        await session.commit()

        await engine.delete(session, user, record.id, secure=False)
        await session.commit()

        with pytest.raises(ValueError, match="Record not found"):
            await engine.get(session, user, record.id)

    async def test_audit_log(self, session: AsyncSession, user, engine: CryptoDBEngine) -> None:
        plaintext = b"audit me"
        record = await engine.put(session, user, plaintext)
        await session.commit()

        log = await engine.audit_log(session, user)
        assert len(log) > 0
        assert any(e["action"] == "create" and e["resource_id"] == record.id for e in log)

    async def test_ledger_verify(self, session: AsyncSession, user, engine: CryptoDBEngine) -> None:
        plaintext = b"verify me"
        await engine.put(session, user, plaintext)
        await session.commit()

        failures = await engine.verify_ledger()
        assert failures == []

    async def test_he_fields(self, session: AsyncSession, user, engine: CryptoDBEngine) -> None:
        engine.init_he_keypair()
        record = await engine.put(session, user, b"salary data", he_fields={"salary": 50000.0})
        await session.commit()

        retrieved = await engine.get(session, user, record.id)
        assert retrieved == b"salary data"

    async def test_he_sum(self, session: AsyncSession, user, engine: CryptoDBEngine) -> None:
        engine.init_he_keypair()
        r1 = await engine.put(session, user, b"a", he_fields={"amount": 100.0})
        r2 = await engine.put(session, user, b"b", he_fields={"amount": 200.0})
        r3 = await engine.put(session, user, b"c", he_fields={"amount": 300.0})
        await session.commit()

        enc_sum = await engine.he_sum(session, user, [r1.id, r2.id, r3.id], "amount")
        decrypted = await engine.he_decrypt_aggregate(session, user, enc_sum)
        assert abs(decrypted - 600.0) < 0.1

    async def test_replication_disabled_by_default(self, session: AsyncSession, user, engine: CryptoDBEngine) -> None:
        # By default replication_enabled is False, so _repl should be None
        assert engine._repl is None

    async def test_replication_enabled_no_nodes(self, session: AsyncSession, user) -> None:
        from cryptodb.crypto.keystore import MasterKeyStore
        from cryptodb.replication.engine import ReplicationEngine
        kek = MasterKeyStore().create_master_key("test")
        repl = ReplicationEngine()
        engine = CryptoDBEngine(kek, replication_engine=repl)
        settings.replication_enabled = True
        try:
            record = await engine.put(session, user, b"replicated data")
            await session.commit()
            # No nodes registered, so replication should silently do nothing
            assert record is not None
        finally:
            settings.replication_enabled = False
