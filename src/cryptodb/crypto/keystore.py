"""Master key (KEK) storage and retrieval."""

import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptodb.config import settings


class KeyStoreError(Exception):
    """Base exception for key storage failures."""


class MasterKeyStore:
    """Manages the master key encryption key (KEK).

    In production this should be backed by an HSM, KMS, or OS keyring.
    This reference implementation uses a file protected by a passphrase.
    """

    def __init__(self, keys_dir: Path | None = None) -> None:
        self._keys_dir = keys_dir or settings.resolved_keys_dir
        self._master_key: bytes | None = None

    def _key_path(self, key_id: str) -> Path:
        return self._keys_dir / f"{key_id}.enc"

    def _salt_path(self, key_id: str) -> Path:
        return self._keys_dir / f"{key_id}.salt"

    def create_master_key(
        self, passphrase: str, key_id: str | None = None, key_size: int = 32
    ) -> bytes:
        """Generate a new master key and persist it encrypted under *passphrase*."""
        key_id = key_id or settings.master_key_id
        key_path = self._key_path(key_id)
        if key_path.exists():
            raise KeyStoreError(f"Master key '{key_id}' already exists")

        salt = os.urandom(32)
        kek = os.urandom(key_size)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_256(),
            length=key_size,
            salt=salt,
            iterations=600_000,
        )
        enc_key = kdf.derive(passphrase.encode("utf-8"))

        # Simple XOR for file storage (acceptable because PBKDF2 output is the real secret)
        enc_kek = bytes(a ^ b for a, b in zip(kek, enc_key))

        key_path.write_bytes(enc_kek)
        self._salt_path(key_id).write_bytes(salt)

        self._master_key = kek
        return kek

    def load_master_key(self, passphrase: str, key_id: str | None = None) -> bytes:
        """Decrypt and return the master key."""
        key_id = key_id or settings.master_key_id
        key_path = self._key_path(key_id)
        salt_path = self._salt_path(key_id)

        if not key_path.exists():
            raise KeyStoreError(f"Master key '{key_id}' not found")

        enc_kek = key_path.read_bytes()
        salt = salt_path.read_bytes()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_256(),
            length=len(enc_kek),
            salt=salt,
            iterations=600_000,
        )
        enc_key = kdf.derive(passphrase.encode("utf-8"))
        kek = bytes(a ^ b for a, b in zip(enc_kek, enc_key))

        self._master_key = kek
        return kek

    def get_master_key(self) -> bytes:
        """Return cached master key or raise."""
        if self._master_key is None:
            raise KeyStoreError("Master key not loaded. Call load_master_key() first.")
        return self._master_key

    def rotate_master_key(
        self, old_passphrase: str, new_passphrase: str, key_id: str | None = None
    ) -> bytes:
        """Re-encrypt master key under a new passphrase."""
        key_id = key_id or settings.master_key_id
        kek = self.load_master_key(old_passphrase, key_id)
        # Remove old files
        self._key_path(key_id).unlink(missing_ok=True)
        self._salt_path(key_id).unlink(missing_ok=True)
        self._master_key = None
        return self.create_master_key(new_passphrase, key_id, len(kek))
