"""Integration tests for the REST API."""

import base64

import pytest
from httpx import ASGITransport, AsyncClient

from cryptodb.api.main import create_app
from cryptodb.auth.session import create_access_token
from cryptodb.crypto.keystore import MasterKeyStore
from cryptodb.db.connection import init_db
from cryptodb.engine import CryptoDBEngine


@pytest.fixture
async def client(db_session, admin_user, engine):
    app = create_app()
    # Override engine state in routes module
    from cryptodb.api import routes as routes_mod
    routes_mod._engine = engine
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


class TestAuthFlow:
    async def test_register_and_login(self, client: AsyncClient) -> None:
        r = await client.post("/api/v1/auth/register", json={"username": "alice", "password": "secret"})
        assert r.status_code == 200
        data = r.json()
        assert "user_id" in data

        r = await client.post("/api/v1/auth/login", json={"username": "alice", "password": "secret"})
        assert r.status_code == 200
        tokens = r.json()
        assert "access_token" in tokens
        assert "refresh_token" in tokens


class TestRecords:
    async def test_put_get_delete(self, client: AsyncClient, admin_user) -> None:
        # Login as admin
        token = create_access_token(admin_user.id)

        payload = base64.b64encode(b"my secret data").decode()
        r = await client.post(
            "/api/v1/records",
            json={"data_b64": payload},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        record_id = r.json()["record_id"]

        r = await client.get(
            f"/api/v1/records/{record_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        retrieved = base64.b64decode(r.json()["data_b64"])
        assert retrieved == b"my secret data"

        r = await client.delete(
            f"/api/v1/records/{record_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

    async def test_audit_requires_auth(self, client: AsyncClient) -> None:
        r = await client.get("/api/v1/audit")
        assert r.status_code == 401

    async def test_health(self, client: AsyncClient) -> None:
        r = await client.get("/api/v1/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    async def test_ledger_verify(self, client: AsyncClient, admin_user) -> None:
        token = create_access_token(admin_user.id)
        r = await client.post(
            "/api/v1/ledger/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert r.json()["tampered"] is False
