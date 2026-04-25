"""Unit tests for key management, recovery, and scheduler API endpoints."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from cryptodb.api.dependencies import get_current_user, get_db
from cryptodb.api.main import create_app


@pytest.fixture
def client():
    app = create_app()
    user = MagicMock()
    user.id = "u-admin"
    user.username = "admin"
    user.role = "admin"
    user.is_active = True
    app.dependency_overrides[get_current_user] = lambda: user

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_session.execute.return_value = mock_result
    async def _mock_db():
        yield mock_session
    app.dependency_overrides[get_db] = _mock_db

    return TestClient(app)


@pytest.fixture
def admin_headers():
    return {"Authorization": "Bearer admin-token"}


# ------------------------------------------------------------------
# Key versions
# ------------------------------------------------------------------

def test_list_key_versions(client, admin_headers):
    with patch("cryptodb.api.routes.MasterKeyStore") as MockKS, \
         patch("cryptodb.api.routes.settings") as mock_settings:
        ks = MagicMock()
        ks.list_key_versions.return_value = ["k1", "k2"]
        MockKS.return_value = ks
        mock_settings.master_key_id = "k2"
        resp = client.get("/api/v1/master-key/versions", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["active"] == "k2"
        assert data["versions"] == ["k1", "k2"]


# ------------------------------------------------------------------
# Rotation
# ------------------------------------------------------------------

def test_rotate_key(client, admin_headers):
    with patch("cryptodb.api.routes.MasterKeyStore") as MockKS, \
         patch("cryptodb.crypto.rotation.RotationScheduler") as MockSched, \
         patch("cryptodb.api.routes.CryptoDBEngine") as MockEngine, \
         patch("cryptodb.api.routes.ReplicationEngine") as MockRepl, \
         patch("cryptodb.api.routes.settings") as mock_settings:

        ks = MagicMock()
        ks.list_key_versions.return_value = ["k-old", "k-new"]
        ks.load_master_key.return_value = b"key"
        MockKS.return_value = ks

        sched = MagicMock()
        sched.run_auto_rotation = AsyncMock(return_value="k-new")
        MockSched.return_value = sched

        mock_engine = MagicMock()
        MockEngine.return_value = mock_engine
        MockEngine.load_chain = AsyncMock(return_value=MagicMock())

        mock_settings.master_key_id = "k-new"
        mock_settings.replication_enabled = False

        resp = client.post("/api/v1/master-key/rotate", json={"passphrase": "secret"}, headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["new_key_id"] == "k-new"
        assert data["status"] == "rotated"


# ------------------------------------------------------------------
# Scheduler
# ------------------------------------------------------------------

def test_scheduler_get(client, admin_headers):
    with patch("cryptodb.crypto.rotation.RotationScheduler") as MockSched:
        state = MagicMock()
        state.auto_rotate = True
        state.interval_hours = 168
        state.last_rotation = datetime(2024, 1, 1, tzinfo=timezone.utc)
        sched = MagicMock()
        sched._state = state
        sched.get_next_rotation.return_value = datetime(2024, 1, 8, tzinfo=timezone.utc)
        MockSched.return_value = sched
        resp = client.get("/api/v1/master-key/scheduler", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["auto_rotate"] is True
        assert data["interval_hours"] == 168
        assert data["last_rotation"] is not None


def test_scheduler_post(client, admin_headers):
    with patch("cryptodb.crypto.rotation.RotationScheduler") as MockSched:
        state = MagicMock()
        state.auto_rotate = False
        state.interval_hours = 72
        state.last_rotation = None
        sched = MagicMock()
        sched._state = state
        sched.get_next_rotation.return_value = None
        MockSched.return_value = sched
        resp = client.post("/api/v1/master-key/scheduler", json={"auto_rotate": False, "interval_hours": 72}, headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["auto_rotate"] is False
        assert data["interval_hours"] == 72


# ------------------------------------------------------------------
# Recovery
# ------------------------------------------------------------------

def test_recovery_split(client, admin_headers):
    with patch("cryptodb.crypto.recovery.split_secret") as mock_split, \
         patch("cryptodb.crypto.keystore.MasterKeyStore") as MockKS:
        ks = MagicMock()
        ks.load_master_key.return_value = b"master-key-secret"
        MockKS.return_value = ks

        share_mock = MagicMock()
        share_mock.to_b64.return_value = "share-b64"
        mock_split.return_value = [share_mock, share_mock]
        resp = client.post(
            "/api/v1/master-key/recovery/split",
            json={"passphrase": "pass", "threshold": 2, "total_shares": 3},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["shares"] == ["share-b64", "share-b64"]


def test_recovery_combine(client, admin_headers):
    with patch("cryptodb.crypto.recovery.recover_secret") as mock_recover, \
         patch("cryptodb.crypto.recovery.Share") as MockShare, \
         patch("cryptodb.crypto.keystore.MasterKeyStore") as MockKS, \
         patch("cryptodb.api.routes.CryptoDBEngine") as MockEngine, \
         patch("cryptodb.api.routes.ReplicationEngine") as MockRepl, \
         patch("cryptodb.api.routes.settings") as mock_settings:
        ks = MagicMock()
        ks.create_master_key.return_value = "k-recovered"
        MockKS.return_value = ks

        share_obj = MagicMock()
        MockShare.from_b64.return_value = share_obj
        mock_recover.return_value = b"master-key-secret"

        mock_engine = MagicMock()
        MockEngine.return_value = mock_engine
        MockEngine.load_chain = AsyncMock(return_value=MagicMock())

        mock_settings.master_key_id = "k-recovered"
        mock_settings.replication_enabled = False

        resp = client.post(
            "/api/v1/master-key/recovery/combine",
            json={"shares": ["share1", "share2"]},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["key_id"] == "k-recovered"
        assert data["status"] == "recovered"
