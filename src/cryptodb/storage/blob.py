"""Encrypted blob storage on local filesystem."""

import hashlib
import os
from pathlib import Path

import aiofiles

from cryptodb.config import settings


class BlobStore:
    """Store and retrieve encrypted byte blobs in a sharded directory layout."""

    def __init__(self, base_dir: Path | None = None) -> None:
        self._base_dir = base_dir or settings.resolved_blob_dir
        self._base_dir.mkdir(parents=True, exist_ok=True)

    def _shard_path(self, record_id: str, kind: str = "data") -> Path:
        """Derive a sharded path from a record ID to avoid single-dir limits."""
        hash_id = hashlib.blake2b(record_id.encode(), digest_size=16).hexdigest()
        # Two-level shard: ab/cd/abcde...
        shard_dir = self._base_dir / kind / hash_id[:2] / hash_id[2:4]
        shard_dir.mkdir(parents=True, exist_ok=True)
        return shard_dir / f"{hash_id}.bin"

    async def write(self, record_id: str, ciphertext: bytes, kind: str = "data") -> str:
        """Write *ciphertext* and return the stored path."""
        path = self._shard_path(record_id, kind)
        async with aiofiles.open(path, "wb") as f:
            await f.write(ciphertext)
        return str(path.resolve())

    async def read(self, path: str) -> bytes:
        """Read blob from *path*."""
        async with aiofiles.open(path, "rb") as f:
            return await f.read()

    async def delete(self, path: str) -> None:
        """Remove blob at *path* (best effort)."""
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

    def exists(self, path: str) -> bool:
        return Path(path).exists()
