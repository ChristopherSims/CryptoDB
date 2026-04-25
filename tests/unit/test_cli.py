"""Unit tests for CryptoDB CLI commands."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from cryptodb.cli.main import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.setenv("CRYPTODB_SECRET_KEY", "cli-test-secret-key-for-testing-only")
    monkeypatch.setenv("CRYPTODB_JWT_SECRET", "cli-test-jwt-secret-key-for-testing-only")


# ------------------------------------------------------------------
# init
# ------------------------------------------------------------------

def test_init():
    with patch("cryptodb.cli.main.init_db", new_callable=AsyncMock) as mock_init:
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "Database initialized" in result.output
        mock_init.assert_awaited_once()


# ------------------------------------------------------------------
# create_master_key
# ------------------------------------------------------------------

def test_create_master_key():
    with patch("cryptodb.cli.main.MasterKeyStore") as MockKS:
        instance = MockKS.return_value
        instance.create_master_key = MagicMock()
        result = runner.invoke(app, ["create-master-key"], input="pass\npass\n")
        assert result.exit_code == 0
        assert "Master key created" in result.output
        instance.create_master_key.assert_called_once_with("pass")


# ------------------------------------------------------------------
# rotate_master_key
# ------------------------------------------------------------------

def test_rotate_master_key():
    with patch("cryptodb.cli.main.MasterKeyStore") as MockKS:
        instance = MockKS.return_value
        instance.rotate_master_key = MagicMock()
        result = runner.invoke(app, ["rotate-master-key"], input="old\nnew\nnew\n")
        assert result.exit_code == 0
        assert "Master key rotated" in result.output
        instance.rotate_master_key.assert_called_once_with("old", "new")


# ------------------------------------------------------------------
# Client-based commands (mock CryptoDBClient)
# ------------------------------------------------------------------

@pytest.fixture
def mock_client():
    with patch("cryptodb.cli.main.CryptoDBClient") as MockClient:
        instance = MockClient.return_value
        instance.login = AsyncMock()
        instance.close = AsyncMock()
        instance.put = AsyncMock(return_value={"record_id": "r1", "size_bytes": 4})
        instance.get = AsyncMock(return_value=b"data")
        instance.audit = AsyncMock(return_value=[{"action": "PUT", "timestamp": "2024-01-01T00:00:00Z"}])
        instance.search = AsyncMock(return_value=["r1"])
        instance.list_records = AsyncMock(return_value=[{"id": "r1", "owner_id": "u1", "size_bytes": 4, "cipher_name": "aes"}])
        instance.grant_access = AsyncMock(return_value={"grant_id": "g1"})
        instance.revoke_access = AsyncMock(return_value={"revoked": True})
        instance.purge_deleted = AsyncMock(return_value={"purged": 3})
        instance.list_users = AsyncMock(return_value=[{"id": "u1", "username": "alice", "role": "user", "is_active": True}])
        instance.set_user_role = AsyncMock(return_value={"role": "admin"})
        instance.ledger_export = AsyncMock(return_value={"entries": []})
        instance.list_key_versions = AsyncMock(return_value={"active": 2, "versions": [1, 2]})
        instance.rotate_key = AsyncMock(return_value={"new_key_id": "k2", "rotated_records": 5})
        instance.recovery_split = AsyncMock(return_value={"shares": ["s1", "s2", "s3"]})
        instance.recovery_combine = AsyncMock(return_value={"key_id": "k1", "status": "active"})
        instance.scheduler_status = AsyncMock(return_value={"auto_rotate": True, "interval_hours": 168})
        instance.scheduler_config = AsyncMock(return_value={"auto_rotate": False, "interval_hours": 72})
        yield instance


def test_put(mock_client, tmp_path):
    f = tmp_path / "test.txt"
    f.write_bytes(b"hello")
    result = runner.invoke(
        app,
        ["put", str(f), "--username", "alice", "--password", "secret"],
    )
    assert result.exit_code == 0
    assert "Stored record: r1" in result.output
    mock_client.login.assert_awaited_once_with("alice", "secret")


def test_get(mock_client, tmp_path):
    out = tmp_path / "out.bin"
    result = runner.invoke(
        app,
        ["get", "r1", "--output", str(out), "--username", "alice", "--password", "secret"],
    )
    assert result.exit_code == 0
    assert "Wrote 4 bytes" in result.output
    assert out.read_bytes() == b"data"


def test_audit(mock_client):
    result = runner.invoke(
        app,
        ["audit", "--username", "alice", "--password", "secret"],
    )
    assert result.exit_code == 0
    assert "PUT" in result.output


def test_search(mock_client):
    result = runner.invoke(
        app,
        ["search", "name", "alice", "--username", "alice", "--password", "secret"],
    )
    assert result.exit_code == 0
    assert "r1" in result.output


def test_list_records(mock_client):
    result = runner.invoke(
        app,
        ["list-records", "--username", "alice", "--password", "secret"],
    )
    assert result.exit_code == 0
    assert "r1" in result.output


def test_grant_access(mock_client):
    result = runner.invoke(
        app,
        ["grant-access", "r1", "read", "--user-id", "u2", "--username", "alice", "--password", "secret"],
    )
    assert result.exit_code == 0
    assert "g1" in result.output


def test_revoke_access(mock_client):
    result = runner.invoke(
        app,
        ["revoke-access", "r1", "g1", "--username", "alice", "--password", "secret"],
    )
    assert result.exit_code == 0
    assert "Revoked" in result.output


def test_purge_deleted(mock_client):
    result = runner.invoke(
        app,
        ["purge-deleted", "--username", "alice", "--password", "secret"],
    )
    assert result.exit_code == 0
    assert "Purged 3 records" in result.output


def test_user_list(mock_client):
    result = runner.invoke(
        app,
        ["user-list", "--username", "alice", "--password", "secret"],
    )
    assert result.exit_code == 0
    assert "alice" in result.output


def test_user_set_role(mock_client):
    result = runner.invoke(
        app,
        ["user-set-role", "u1", "admin", "--username", "alice", "--password", "secret"],
    )
    assert result.exit_code == 0
    assert "Updated" in result.output


def test_ledger_export(mock_client, tmp_path):
    out = tmp_path / "ledger.json"
    result = runner.invoke(
        app,
        ["ledger-export", str(out), "--username", "alice", "--password", "secret"],
    )
    assert result.exit_code == 0
    assert "Exported ledger" in result.output
    assert json.loads(out.read_text()) == {"entries": []}


def test_key_versions(mock_client):
    result = runner.invoke(
        app,
        ["key-versions", "--username", "alice", "--password", "secret"],
    )
    assert result.exit_code == 0
    assert "Active: 2" in result.output


def test_rotate_key(mock_client):
    result = runner.invoke(
        app,
        ["rotate-key", "--username", "alice", "--password", "secret"],
        input="pass\n",
    )
    assert result.exit_code == 0
    assert "k2" in result.output


def test_recovery_split(mock_client):
    result = runner.invoke(
        app,
        ["recovery-split", "--threshold", "2", "--shares", "3", "--username", "alice", "--password", "secret"],
        input="pass\n",
    )
    assert result.exit_code == 0
    assert "Share 1" in result.output
    mock_client.recovery_split.assert_awaited_once_with("pass", 2, 3)


def test_recovery_combine(mock_client):
    result = runner.invoke(
        app,
        ["recovery-combine", "s1", "s2", "--username", "alice", "--password", "secret"],
    )
    assert result.exit_code == 0
    assert "k1" in result.output


def test_scheduler_status(mock_client):
    result = runner.invoke(
        app,
        ["scheduler-status", "--username", "alice", "--password", "secret"],
    )
    assert result.exit_code == 0
    assert "Auto-rotate: True" in result.output


def test_scheduler_config(mock_client):
    result = runner.invoke(
        app,
        ["scheduler-config", "--no-auto-rotate", "--interval-hours", "72", "--username", "alice", "--password", "secret"],
    )
    assert result.exit_code == 0
    assert "Auto-rotate: False" in result.output
    mock_client.scheduler_config.assert_awaited_once_with(auto_rotate=False, interval_hours=72)
