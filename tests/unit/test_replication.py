"""Unit tests for the replication engine."""

import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.auth.users import create_user
from cryptodb.config import settings
from cryptodb.db.connection import get_session_local, init_db, reset_engine
from cryptodb.db.metadata import Record, ReplicationLog, ReplicationNode
from cryptodb.engine import CryptoDBEngine
from cryptodb.replication.engine import ReplicationEngine


@pytest.fixture(autouse=True)
def temp_dirs():
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        from pathlib import Path
        settings.data_dir = Path(os.path.join(tmpdir, "data"))
        settings.blob_dir = Path(os.path.join(tmpdir, "data", "blobs"))
        settings.db_path = Path(os.path.join(tmpdir, "data", "cryptodb.db"))
        settings.keys_dir = Path(os.path.join(tmpdir, "data", "keys"))
        settings.replication_allow_http = True
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
async def admin(session: AsyncSession):
    return await create_user(session, "admin", "adminpass", role="admin")


@pytest.fixture
async def reader(session: AsyncSession):
    return await create_user(session, "reader", "readerpass", role="reader")


@pytest.fixture
def repl_engine():
    return ReplicationEngine()


class TestRegisterNode:
    async def test_register_success(self, session: AsyncSession, admin, repl_engine: ReplicationEngine) -> None:
        node, token = await repl_engine.register_node(session, admin, "standby-1", "http://localhost:9001")
        await session.commit()
        assert node.name == "standby-1"
        assert node.endpoint_url == "http://localhost:9001"
        assert node.status == "active"
        assert len(token) > 20
        assert hashlib.sha3_256(token.encode()).hexdigest() == node.auth_token_hash

    async def test_register_denied_for_reader(self, session: AsyncSession, reader, repl_engine: ReplicationEngine) -> None:
        with pytest.raises(PermissionError):
            await repl_engine.register_node(session, reader, "standby-1", "http://localhost:9001")

    async def test_unregister_node(self, session: AsyncSession, admin, repl_engine: ReplicationEngine) -> None:
        node, _ = await repl_engine.register_node(session, admin, "standby-1", "http://localhost:9001")
        await session.commit()
        await repl_engine.unregister_node(session, admin, node.id)
        await session.commit()

        result = await session.execute(
            __import__("sqlalchemy", fromlist=["select"]).select(ReplicationNode).where(ReplicationNode.id == node.id)
        )
        assert result.scalar_one_or_none() is None


class TestSyncRecord:
    async def test_sync_record_to_active_nodes(self, session: AsyncSession, admin, repl_engine: ReplicationEngine) -> None:
        from cryptodb.crypto.keystore import MasterKeyStore
        kek = MasterKeyStore().create_master_key("test")
        engine = CryptoDBEngine(kek, replication_engine=repl_engine)

        # Create a record
        record = await engine.put(session, admin, b"secret payload")
        await session.commit()

        # Register a standby node (mocked endpoint)
        node, _ = await repl_engine.register_node(session, admin, "standby-mock", "http://mock-standby:8000/api/v1")
        await session.commit()

        # Mock httpx client post
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"checksum_ok": True}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            logs = await repl_engine.sync_record(session, record)
            await session.commit()

        assert len(logs) == 1
        assert logs[0].status == "acked"
        assert logs[0].record_id == record.id
        assert logs[0].node_id == node.id

    async def test_sync_no_nodes(self, session: AsyncSession, admin, repl_engine: ReplicationEngine) -> None:
        from cryptodb.crypto.keystore import MasterKeyStore
        kek = MasterKeyStore().create_master_key("test")
        engine = CryptoDBEngine(kek, replication_engine=repl_engine)
        record = await engine.put(session, admin, b"payload")
        await session.commit()

        logs = await repl_engine.sync_record(session, record, nodes=[])
        assert logs == []


class TestRetryPending:
    async def test_retry_failed_replication(self, session: AsyncSession, admin, repl_engine: ReplicationEngine) -> None:
        from cryptodb.crypto.keystore import MasterKeyStore
        kek = MasterKeyStore().create_master_key("test")
        engine = CryptoDBEngine(kek, replication_engine=repl_engine)

        record = await engine.put(session, admin, b"retry payload")
        await session.commit()

        node, _ = await repl_engine.register_node(session, admin, "standby-retry", "http://mock:8000/api/v1")
        await session.commit()

        # Create a pending log manually
        log = ReplicationLog(
            record_id=record.id,
            node_id=node.id,
            status="failed",
            retry_count=1,
            blob_checksum="abcd",
            metadata_snapshot={},
            sequence_number=1,
        )
        session.add(log)
        await session.commit()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"checksum_ok": True}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            retried = await repl_engine.retry_pending(session, max_retries=3)
            await session.commit()

        assert len(retried) == 1
        assert retried[0].status == "acked"


class TestHealthCheck:
    async def test_health_check_marks_unhealthy(self, session: AsyncSession, admin, repl_engine: ReplicationEngine) -> None:
        node, _ = await repl_engine.register_node(session, admin, "standby-bad", "http://localhost:99999/api/v1")
        await session.commit()

        outcomes = await repl_engine.health_check_nodes(session)
        await session.commit()

        assert any(o[0] == node.id and o[1] is False for o in outcomes)
        assert node.status == "unhealthy"
