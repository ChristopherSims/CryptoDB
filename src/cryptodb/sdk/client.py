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

