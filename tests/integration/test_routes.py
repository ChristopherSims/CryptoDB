"""Integration tests for API routes coverage."""

import base64

import pytest
from httpx import ASGITransport, AsyncClient

from cryptodb.api.main import create_app
from cryptodb.auth.session import create_access_token
from cryptodb.db.connection import init_db
from cryptodb.db.metadata import User
from cryptodb.engine import CryptoDBEngine


@pytest.fixture
async def client(db_session, admin_user, engine):
    app = create_app()
    from cryptodb.api import routes as routes_mod
    routes_mod._engine = engine
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture
async def token(admin_user):
    return create_access_token(admin_user.id)


class TestRecordsExtended:
    async def test_put_with_index_fields(self, client, token):
        payload = base64.b64encode(b"hello").decode()
        r = await client.post(
            "/api/v1/records",
            json={"data_b64": payload, "searchable_fields": {"email": "a@b.com"}},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        rid = r.json()["record_id"]
        assert rid

    async def test_put_too_large(self, client, token):
        big = base64.b64encode(b"x" * 11_000_000).decode()
        r = await client.post(
            "/api/v1/records",
            json={"data_b64": big},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 413

    async def test_get_not_found(self, client, token):
        r = await client.get("/api/v1/records/nope", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 404

    async def test_delete_not_found(self, client, token):
        r = await client.delete("/api/v1/records/nope", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 404

    async def test_list_records(self, client, token):
        r = await client.get("/api/v1/records", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    async def test_list_pagination(self, client, token):
        r = await client.get("/api/v1/records?page=1&page_size=5", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    async def test_search_by_index(self, client, token):
        payload = base64.b64encode(b"data").decode()
        await client.post(
            "/api/v1/records",
            json={"data_b64": payload, "searchable_fields": {"email": "find@me.com"}},
            headers={"Authorization": f"Bearer {token}"},
        )
        r = await client.post(
            "/api/v1/records/search",
            json={"field_name": "email", "value": "find@me.com"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    async def test_search_missing_params(self, client, token):
        r = await client.post("/api/v1/records/search", json={}, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 422


class TestACL:
    async def test_grant_and_list(self, client, token, db_session, admin_user):
        payload = base64.b64encode(b"acl data").decode()
        r = await client.post(
            "/api/v1/records",
            json={"data_b64": payload},
            headers={"Authorization": f"Bearer {token}"},
        )
        rid = r.json()["record_id"]
        other = User(username="otheruser", password_hash="x", role="reader")
        db_session.add(other)
        await db_session.flush()
        await db_session.commit()

        r = await client.post(
            f"/api/v1/records/{rid}/grants",
            json={"user_id": other.id, "permission": "read"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

        r = await client.get(
            f"/api/v1/records/{rid}/grants",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        grants = r.json()
        assert any(g["permission"] == "read" for g in grants)

    async def test_revoke_acl(self, client, token, db_session, admin_user):
        payload = base64.b64encode(b"revoke data").decode()
        r = await client.post(
            "/api/v1/records",
            json={"data_b64": payload},
            headers={"Authorization": f"Bearer {token}"},
        )
        rid = r.json()["record_id"]
        other = User(username="revokeuser", password_hash="x", role="reader")
        db_session.add(other)
        await db_session.flush()
        await db_session.commit()

        await client.post(
            f"/api/v1/records/{rid}/grants",
            json={"user_id": other.id, "permission": "read"},
            headers={"Authorization": f"Bearer {token}"},
        )
        r = await client.delete(
            f"/api/v1/records/{rid}/grants",
            json={"user_id": other.id, "permission": "read"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200


class TestUsers:
    async def test_list_users(self, client, token):
        r = await client.get("/api/v1/users", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    async def test_set_role(self, client, token, db_session):
        u = User(username="roletest", password_hash="x", role="reader")
        db_session.add(u)
        await db_session.flush()
        await db_session.commit()
        r = await client.patch(
            f"/api/v1/users/{u.id}/role",
            json={"role": "writer"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

    async def test_delete_user(self, client, token, db_session):
        u = User(username="deluser", password_hash="x", role="reader")
        db_session.add(u)
        await db_session.flush()
        await db_session.commit()
        r = await client.delete(
            f"/api/v1/users/{u.id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 204

    async def test_disable_user(self, client, token, db_session):
        u = User(username="disuser", password_hash="x", role="reader")
        db_session.add(u)
        await db_session.flush()
        await db_session.commit()
        r = await client.patch(
            f"/api/v1/users/{u.id}/disable",
            json={"disabled": True},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200


class TestAdmin:
    async def test_purge_deleted(self, client, token):
        r = await client.post("/api/v1/admin/purge-deleted", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert "deleted" in r.json()

    async def test_integrity_scan(self, client, token):
        r = await client.post("/api/v1/admin/integrity-scan", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    async def test_metrics(self, client, token):
        r = await client.get("/api/v1/metrics", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    async def test_audit(self, client, token):
        r = await client.get("/api/v1/audit", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    async def test_audit_anomalies(self, client, token):
        r = await client.get("/api/v1/audit/anomalies", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    async def test_ledger_export(self, client, token):
        r = await client.post("/api/v1/ledger/export", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert "records" in r.json()


class TestReplication:
    async def test_get_changes(self, client, token):
        r = await client.get("/api/v1/replication/changes?since=0", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    async def test_reset_sync(self, client, token):
        r = await client.post("/api/v1/replication/reset-sync", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    async def test_dead_letter(self, client, token):
        r = await client.get("/api/v1/replication/dead-letter", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200


class TestKeyMgmt:
    async def test_list_keys(self, client, token):
        r = await client.get("/api/v1/keys", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    async def test_rotate(self, client, token):
        r = await client.post("/api/v1/keys/rotate", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    async def test_recovery_split(self, client, token):
        r = await client.post("/api/v1/keys/recovery-split", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert "shares" in r.json()

    async def test_recovery_combine(self, client, token):
        r = await client.post("/api/v1/keys/recovery-split", headers={"Authorization": f"Bearer {token}"})
        shares = r.json()["shares"]
        r2 = await client.post(
            "/api/v1/keys/recovery-combine",
            json={"shares": shares},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r2.status_code == 200

    async def test_scheduler_status(self, client, token):
        r = await client.get("/api/v1/keys/scheduler-status", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200


class TestAuth:
    async def test_refresh(self, client):
        r = await client.post("/api/v1/auth/register", json={"username": "refr", "password": "***"})
        assert r.status_code == 200
        r = await client.post("/api/v1/auth/login", json={"username": "refr", "password": "***"})
        tokens = r.json()
        refresh = tokens["refresh_token"]
        r = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert r.status_code == 200
        assert "access_token" in r.json()

    async def test_logout(self, client):
        r = await client.post("/api/v1/auth/register", json={"username": "logout", "password": "***"})
        assert r.status_code == 200
        r = await client.post("/api/v1/auth/login", json={"username": "logout", "password": "***"})
        tokens = r.json()
        access = tokens["access_token"]
        r = await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {access}"})
        assert r.status_code == 200
