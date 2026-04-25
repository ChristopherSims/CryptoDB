"""Unit tests for CryptoDB SDK client (mocked httpx)."""

import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cryptodb.sdk.client import CryptoDBClient, TokenPair


@pytest.fixture
def client():
    return CryptoDBClient(base_url="http://test/api/v1")


@pytest.fixture
def mock_response():
    def _make(json_data=None, status_code=200):
        r = MagicMock()
        r.json.return_value = json_data if json_data is not None else {}
        r.status_code = status_code
        r.raise_for_status = MagicMock()
        return r
    return _make


@pytest.fixture(autouse=True)
def _patch_client():
    with patch("cryptodb.sdk.client.httpx.AsyncClient") as MockClient:
        instance = MockClient.return_value
        instance.post = AsyncMock()
        instance.get = AsyncMock()
        instance.delete = AsyncMock()
        instance.patch = AsyncMock()
        yield instance


# ------------------------------------------------------------------
# Auth
# ------------------------------------------------------------------

async def test_register(client, _patch_client, mock_response):
    _patch_client.post.return_value = mock_response({"id": "u1"})
    result = await client.register("alice", "secret")
    assert result == {"id": "u1"}
    _patch_client.post.assert_awaited_once()


async def test_login_sets_token(client, _patch_client, mock_response):
    _patch_client.post.return_value = mock_response(
        {"access_token": "acc", "refresh_token": "ref"}
    )
    pair = await client.login("alice", "secret")
    assert pair == TokenPair(access_token="acc", refresh_token="ref")
    assert client._token == "acc"


async def test_logout_clears_token(client, _patch_client, mock_response):
    client._token = "acc"
    _patch_client.post.return_value = mock_response({"message": "ok"})
    result = await client.logout()
    assert client._token is None
    assert result == {"message": "ok"}


async def test_refresh(client, _patch_client, mock_response):
    _patch_client.post.return_value = mock_response(
        {"access_token": "new", "refresh_token": "new_ref"}
    )
    pair = await client.refresh("old_ref")
    assert pair.access_token == "new"
    assert client._token == "new"


# ------------------------------------------------------------------
# Init / Master key
# ------------------------------------------------------------------

async def test_init_db(client, _patch_client, mock_response):
    _patch_client.post.return_value = mock_response({})
    await client.init_db()
    _patch_client.post.assert_awaited_once()


async def test_setup_master_key(client, _patch_client, mock_response):
    _patch_client.post.return_value = mock_response({"key_id": "k1"})
    result = await client.setup_master_key("pass")
    assert result == {"key_id": "k1"}


async def test_unlock_master_key(client, _patch_client, mock_response):
    _patch_client.post.return_value = mock_response({"key_id": "k1"})
    result = await client.unlock_master_key("pass")
    assert result == {"key_id": "k1"}


# ------------------------------------------------------------------
# Records
# ------------------------------------------------------------------

async def test_put_requires_auth(client):
    with pytest.raises(RuntimeError, match="Not authenticated"):
        await client.put(b"data")


async def test_put(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"id": "r1"})
    result = await client.put(b"hello", cipher_name="aes-256-gcm", searchable={"a": "b"})
    assert result == {"id": "r1"}
    call = _patch_client.post.call_args
    assert call.kwargs["headers"]["Authorization"] == "Bearer tok"
    payload = call.kwargs["json"]
    assert payload["compress"] == "zstd"
    assert base64.b64decode(payload["data_b64"]) == b"hello"
    assert payload["cipher_name"] == "aes-256-gcm"
    assert payload["searchable"] == {"a": "b"}


async def test_get(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.get.return_value = mock_response({"data_b64": base64.b64encode(b"hello").decode()})
    result = await client.get("r1")
    assert result == b"hello"


async def test_delete(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.delete.return_value = mock_response({"deleted": True})
    result = await client.delete("r1", secure=True)
    assert result == {"deleted": True}
    call = _patch_client.delete.call_args
    assert call.kwargs["params"]["secure"] is True


# ------------------------------------------------------------------
# Search / List
# ------------------------------------------------------------------

async def test_search(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"record_ids": ["r1", "r2"]})
    result = await client.search("name", "alice")
    assert result == ["r1", "r2"]


async def test_list_records(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.get.return_value = mock_response([{"id": "r1"}])
    result = await client.list_records(page=2, page_size=10)
    assert result == [{"id": "r1"}]


# ------------------------------------------------------------------
# Audit
# ------------------------------------------------------------------

async def test_audit(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.get.return_value = mock_response([{"action": "PUT"}])
    result = await client.audit()
    assert result == [{"action": "PUT"}]


# ------------------------------------------------------------------
# HE
# ------------------------------------------------------------------

async def test_init_he(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"context_id": "c1"})
    result = await client.init_he()
    assert result == {"context_id": "c1"}


async def test_he_sum(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"encrypted_sum": {"c0": 1}})
    result = await client.he_sum(["r1"], "field")
    assert result == {"encrypted_sum": {"c0": 1}}


async def test_he_decrypt(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"value": 42.0})
    result = await client.he_decrypt({"c0": 1})
    assert result == {"value": 42.0}


# ------------------------------------------------------------------
# ACL
# ------------------------------------------------------------------

async def test_grant_access(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"grant_id": "g1"})
    result = await client.grant_access("r1", "read", user_id="u2")
    assert result == {"grant_id": "g1"}


async def test_revoke_access(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.delete.return_value = mock_response({"revoked": True})
    result = await client.revoke_access("r1", "g1")
    assert result == {"revoked": True}


async def test_list_grants(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.get.return_value = mock_response([{"grant_id": "g1"}])
    result = await client.list_grants("r1")
    assert result == [{"grant_id": "g1"}]


# ------------------------------------------------------------------
# Users
# ------------------------------------------------------------------

async def test_list_users(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.get.return_value = mock_response([{"id": "u1"}])
    result = await client.list_users()
    assert result == [{"id": "u1"}]


async def test_set_user_role(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.patch.return_value = mock_response({"role": "admin"})
    result = await client.set_user_role("u1", "admin")
    assert result == {"role": "admin"}


# ------------------------------------------------------------------
# Replication
# ------------------------------------------------------------------

async def test_register_standby(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"node_id": "n1"})
    result = await client.register_standby("s1", "http://s1")
    assert result == {"node_id": "n1"}


async def test_list_standbys(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.get.return_value = mock_response([{"id": "n1"}])
    result = await client.list_standbys()
    assert result == [{"id": "n1"}]


async def test_unregister_standby(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.delete.return_value = mock_response({"removed": True})
    result = await client.unregister_standby("n1")
    assert result == {"removed": True}


async def test_replication_health_check(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response([{"status": "ok"}])
    result = await client.replication_health_check()
    assert result == [{"status": "ok"}]


async def test_replication_retry(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response([{"retried": True}])
    result = await client.replication_retry()
    assert result == [{"retried": True}]


# ------------------------------------------------------------------
# Hardware tokens
# ------------------------------------------------------------------

async def test_hardware_register_begin(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"challenge_token": "ct"})
    result = await client.hardware_register_begin()
    assert result == {"challenge_token": "ct"}


async def test_hardware_register_finish(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"credential_id": "c1"})
    result = await client.hardware_register_finish("ct", {"sig": "x"})
    assert result == {"credential_id": "c1"}


async def test_hardware_authenticate_begin(client, _patch_client, mock_response):
    _patch_client.post.return_value = mock_response({"challenge_token": "ct"})
    result = await client.hardware_authenticate_begin("alice", "secret")
    assert result == {"challenge_token": "ct"}


async def test_hardware_authenticate_finish(client, _patch_client, mock_response):
    _patch_client.post.return_value = mock_response(
        {"access_token": "acc", "refresh_token": "ref"}
    )
    pair = await client.hardware_authenticate_finish("ct", {"sig": "x"})
    assert pair.access_token == "acc"
    assert client._token == "acc"


# ------------------------------------------------------------------
# Seal / Unseal / Purge / Export
# ------------------------------------------------------------------

async def test_seal_master_key(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"sealed_blob_b64": "abc"})
    result = await client.seal_master_key("pass")
    assert result == {"sealed_blob_b64": "abc"}


async def test_unseal_master_key(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"key_id": "k1"})
    result = await client.unseal_master_key("pass", "abc")
    assert result == {"key_id": "k1"}


async def test_purge_deleted(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"purged": 3})
    result = await client.purge_deleted()
    assert result == {"purged": 3}


async def test_ledger_export(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.get.return_value = mock_response({"entries": []})
    result = await client.ledger_export(fmt="csv", start_date="2024-01-01")
    assert result == {"entries": []}


# ------------------------------------------------------------------
# Key management
# ------------------------------------------------------------------

async def test_list_key_versions(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.get.return_value = mock_response({"versions": [1, 2]})
    result = await client.list_key_versions()
    assert result == {"versions": [1, 2]}


async def test_rotate_key(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"new_key_id": "k2"})
    result = await client.rotate_key("pass")
    assert result == {"new_key_id": "k2"}


async def test_recovery_split(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"shares": ["s1", "s2"]})
    result = await client.recovery_split("pass", 2, 3)
    assert result == {"shares": ["s1", "s2"]}


async def test_recovery_combine(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"recovered": True})
    result = await client.recovery_combine(["s1", "s2"])
    assert result == {"recovered": True}


async def test_scheduler_status(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.get.return_value = mock_response({"enabled": True})
    result = await client.scheduler_status()
    assert result == {"enabled": True}


# ------------------------------------------------------------------
# Batch helpers
# ------------------------------------------------------------------

async def test_put_batch(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.post.return_value = mock_response({"id": "rx"})
    result = await client.put_batch([b"a", b"b"])
    assert len(result) == 2
    assert _patch_client.post.await_count == 2


async def test_get_batch(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.get.return_value = mock_response(
        {"data_b64": base64.b64encode(b"x").decode()}
    )
    result = await client.get_batch(["r1", "r2"])
    assert len(result) == 2
    assert _patch_client.get.await_count == 2


async def test_delete_batch(client, _patch_client, mock_response):
    client._token = "tok"
    _patch_client.delete.return_value = mock_response({"deleted": True})
    result = await client.delete_batch(["r1", "r2"])
    assert len(result) == 2
    assert _patch_client.delete.await_count == 2
