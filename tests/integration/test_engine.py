"""Integration tests for the CryptoDB engine."""

import os
import tempfile

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.auth.users import create_user
from cryptodb.config import settings
from cryptodb.crypto.keystore import MasterKeyStore
from cryptodb.db.connection import AsyncSessionLocal, init_db
from cryptodb.engine import CryptoDBEngine
from cryptodb.ledger.chain import HashChain


@pytest.fixture(autouse=True)
def temp_dirs():
    with tempfile.TemporaryDirectory() as tmpdir:
        settings.data_dir = os.path.join(tmpdir, "data")
        settings.blob_dir = os.path.join(tmpdir, "data", "blobs")
        settings.db_path = os.path.join(tmpdir, "data", "cryptodb.db")
        settings.keys_dir = os.path.join(tmpdir, "data", "keys")
        yield


@pytest.fixture
async def session():
    await init_db()
    async with AsyncSessionLocal() as s:
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
