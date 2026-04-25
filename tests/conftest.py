"""Shared pytest fixtures."""

import os
import tempfile
from collections.abc import AsyncGenerator

import pytest

from cryptodb.config import settings
from cryptodb.crypto.keystore import MasterKeyStore
from cryptodb.db.connection import AsyncSessionLocal, init_db
from cryptodb.engine import CryptoDBEngine


@pytest.fixture(autouse=True)
def temp_dirs():
    with tempfile.TemporaryDirectory() as tmpdir:
        settings.data_dir = os.path.join(tmpdir, "data")
        settings.blob_dir = os.path.join(tmpdir, "data", "blobs")
        settings.db_path = os.path.join(tmpdir, "data", "cryptodb.db")
        settings.keys_dir = os.path.join(tmpdir, "data", "keys")
        yield


@pytest.fixture
async def db_session() -> AsyncGenerator:
    await init_db()
    async with AsyncSessionLocal() as session:
        yield session
        await session.rollback()


@pytest.fixture
async def admin_user(db_session):
    from cryptodb.auth.users import create_user
    user = await create_user(db_session, "admin", "adminpass", role="admin")
    await db_session.commit()
    return user


@pytest.fixture
async def engine(db_session):
    ks = MasterKeyStore()
    kek = ks.create_master_key("test-passphrase")
    chain = await CryptoDBEngine.load_chain(db_session)
    return CryptoDBEngine(kek, hash_chain=chain)
