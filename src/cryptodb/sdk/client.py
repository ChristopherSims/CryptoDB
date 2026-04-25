"""Python SDK client for CryptoDB."""

import base64
from dataclasses import dataclass

import httpx


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str


class CryptoDBClient:
    """Async HTTP client for the CryptoDB REST API."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000/api/v1") -> None:
        self._base = base_url.rstrip("/")
        self._client = httpx.AsyncClient()
        self._token: str | None = None

    async def close(self) -> None:
        await self._client.aclose()

    async def register(self, username: str, password: str) -> dict:
        r = await self._client.post(
            f"{self._base}/auth/register",
            json={"username": username, "password": password},
        )
        r.raise_for_status()
        return r.json()

    async def login(self, username: str, password: str) -> TokenPair:
        r = await self._client.post(
            f"{self._base}/auth/login",
            json={"username": username, "password": password},
        )
        r.raise_for_status()
        data = r.json()
        self._token = data["access_token"]
        return TokenPair(access_token=data["access_token"], refresh_token=data["refresh_token"])

    async def init_db(self) -> None:
        r = await self._client.post(f"{self._base}/init")
        r.raise_for_status()

    async def setup_master_key(self, passphrase: str) -> dict:
        r = await self._client.post(
            f"{self._base}/master-key",
            params={"passphrase": passphrase},
        )
        r.raise_for_status()
        return r.json()

    async def unlock_master_key(self, passphrase: str) -> dict:
        r = await self._client.post(
            f"{self._base}/master-key/unlock",
            params={"passphrase": passphrase},
        )
        r.raise_for_status()
        return r.json()

    async def put(
        self,
        data: bytes,
        cipher_name: str | None = None,
        compress: str = "zstd",
        searchable: dict[str, str] | None = None,
        he_fields: dict[str, float] | None = None,
    ) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        payload: dict = {
            "data_b64": base64.b64encode(data).decode(),
            "compress": compress,
        }
        if cipher_name:
            payload["cipher_name"] = cipher_name
        if searchable:
            payload["searchable"] = searchable
        if he_fields:
            payload["he_fields"] = he_fields
        r = await self._client.post(
            f"{self._base}/records",
            json=payload,
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def get(self, record_id: str) -> bytes:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.get(
            f"{self._base}/records/{record_id}",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        data = r.json()
        return base64.b64decode(data["data_b64"])

    async def delete(self, record_id: str, secure: bool = False) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.delete(
            f"{self._base}/records/{record_id}",
            headers={"Authorization": f"Bearer {self._token}"},
            params={"secure": secure},
        )
        r.raise_for_status()
        return r.json()

    async def audit(self) -> list[dict]:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.get(
            f"{self._base}/audit",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def init_he(self) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/he/init",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def he_sum(self, record_ids: list[str], field: str) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/he/sum",
            json={"record_ids": record_ids, "field": field},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def he_decrypt(self, encrypted_sum: dict[str, int]) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/he/decrypt",
            json={"encrypted_sum": encrypted_sum},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # Batch operations (client-side concurrency)
    # ------------------------------------------------------------------

    async def put_batch(
        self,
        items: list[bytes],
        cipher_name: str | None = None,
        compress: str = "zstd",
        searchable: dict[str, str] | None = None,
        he_fields: dict[str, float] | None = None,
    ) -> list[dict]:
        import asyncio
        sem = asyncio.Semaphore(10)
        async def _put_one(data: bytes) -> dict:
            async with sem:
                return await self.put(data, cipher_name=cipher_name, compress=compress, searchable=searchable, he_fields=he_fields)
        return await asyncio.gather(*[_put_one(d) for d in items])

    async def get_batch(self, record_ids: list[str]) -> list[bytes]:
        import asyncio
        sem = asyncio.Semaphore(10)
        async def _get_one(rid: str) -> bytes:
            async with sem:
                return await self.get(rid)
        return await asyncio.gather(*[_get_one(rid) for rid in record_ids])

    async def delete_batch(self, record_ids: list[str], secure: bool = False) -> list[dict]:
        import asyncio
        sem = asyncio.Semaphore(10)
        async def _delete_one(rid: str) -> dict:
            async with sem:
                return await self.delete(rid, secure=secure)
        return await asyncio.gather(*[_delete_one(rid) for rid in record_ids])

    # ------------------------------------------------------------------
    # Search & list
    # ------------------------------------------------------------------

    async def search(self, field_name: str, token_plaintext: str) -> list[str]:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/records/search",
            json={"field_name": field_name, "token_plaintext": token_plaintext},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json().get("record_ids", [])

    async def list_records(self, page: int = 1, page_size: int = 20) -> list[dict]:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.get(
            f"{self._base}/records",
            params={"page": page, "page_size": page_size},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    async def logout(self) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/auth/logout",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        self._token = None
        return r.json()

    async def refresh(self, refresh_token: str) -> TokenPair:
        r = await self._client.post(
            f"{self._base}/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        r.raise_for_status()
        data = r.json()
        self._token = data["access_token"]
        return TokenPair(access_token=data["access_token"], refresh_token=data["refresh_token"])

    # ------------------------------------------------------------------
    # ACL management
    # ------------------------------------------------------------------

    async def grant_access(self, record_id: str, permission: str, user_id: str | None = None, role: str | None = None) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/records/{record_id}/grants",
            json={"permission": permission, "user_id": user_id, "role": role},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def revoke_access(self, record_id: str, grant_id: str) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.delete(
            f"{self._base}/records/{record_id}/grants/{grant_id}",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def list_grants(self, record_id: str) -> list[dict]:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.get(
            f"{self._base}/records/{record_id}/grants",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # User management
    # ------------------------------------------------------------------

    async def list_users(self) -> list[dict]:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.get(
            f"{self._base}/users",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def set_user_role(self, user_id: str, role: str) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.patch(
            f"{self._base}/users/{user_id}/role",
            json={"role": role},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # Replication
    # ------------------------------------------------------------------

    async def register_standby(self, name: str, endpoint_url: str) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/replication/nodes",
            json={"name": name, "endpoint_url": endpoint_url},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def list_standbys(self) -> list[dict]:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.get(
            f"{self._base}/replication/nodes",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def unregister_standby(self, node_id: str) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.delete(
            f"{self._base}/replication/nodes/{node_id}",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def replication_health_check(self) -> list[dict]:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/replication/health-check",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def replication_retry(self) -> list[dict]:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/replication/retry",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # Hardware tokens
    # ------------------------------------------------------------------

    async def hardware_register_begin(self, name: str = "Primary Token") -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/auth/hardware/register-begin",
            json={"name": name},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def hardware_register_finish(self, challenge_token: str, client_response: dict) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/auth/hardware/register-finish",
            json={"challenge_token": challenge_token, "client_response": client_response},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def hardware_authenticate_begin(self, username: str, password: str) -> dict:
        r = await self._client.post(
            f"{self._base}/auth/hardware/authenticate-begin",
            json={"username": username, "password": password},
        )
        r.raise_for_status()
        return r.json()

    async def hardware_authenticate_finish(self, challenge_token: str, client_response: dict) -> TokenPair:
        r = await self._client.post(
            f"{self._base}/auth/hardware/authenticate-finish",
            json={"challenge_token": challenge_token, "client_response": client_response},
        )
        r.raise_for_status()
        data = r.json()
        self._token = data["access_token"]
        return TokenPair(access_token=data["access_token"], refresh_token=data["refresh_token"])

    async def seal_master_key(self, passphrase: str) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/master-key/seal",
            json={"passphrase": passphrase},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def unseal_master_key(self, passphrase: str, sealed_blob_b64: str) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/master-key/unseal",
            json={"passphrase": passphrase},
            params={"sealed_blob_b64": sealed_blob_b64},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def purge_deleted(self) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/admin/purge-deleted",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def ledger_export(self, fmt: str = "json", start_date: str | None = None, end_date: str | None = None) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.get(
            f"{self._base}/ledger/export",
            params={"format": fmt, "start_date": start_date, "end_date": end_date},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    async def list_key_versions(self) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.get(
            f"{self._base}/master-key/versions",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def rotate_key(self, passphrase: str) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/master-key/rotate",
            json={"passphrase": passphrase},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def recovery_split(self, passphrase: str, threshold: int, total_shares: int) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/master-key/recovery/split",
            json={"passphrase": passphrase, "threshold": threshold, "total_shares": total_shares},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def recovery_combine(self, shares: list[str]) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.post(
            f"{self._base}/master-key/recovery/combine",
            json={"shares": shares},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def scheduler_status(self) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        r = await self._client.get(
            f"{self._base}/master-key/scheduler",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()

    async def scheduler_config(self, auto_rotate: bool | None = None, interval_hours: int | None = None) -> dict:
        if self._token is None:
            raise RuntimeError("Not authenticated")
        payload: dict = {}
        if auto_rotate is not None:
            payload["auto_rotate"] = auto_rotate
        if interval_hours is not None:
            payload["interval_hours"] = interval_hours
        r = await self._client.post(
            f"{self._base}/master-key/scheduler",
            json=payload,
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return r.json()


