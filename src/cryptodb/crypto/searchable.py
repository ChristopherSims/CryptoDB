"""Deterministic encryption for equality queries on encrypted fields.

WARNING: Deterministic encryption leaks equality relationships.
Use only for fields where this tradeoff is acceptable.
"""

import base64
import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True, slots=True)
class SearchableIndex:
    """A deterministic, queryable token for an encrypted field."""

    token: bytes
    algorithm: str = "hmac-blake2b"

    def to_dict(self) -> dict[str, str]:
        return {
            "token": base64.b64encode(self.token).decode(),
            "algorithm": self.algorithm,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "SearchableIndex":
        return cls(
            token=base64.b64decode(data["token"]),
            algorithm=data.get("algorithm", "hmac-blake2b"),
        )


class SearchableCipher:
    """Produces deterministic ciphertexts / indices for equality search."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("SearchableCipher requires a 32-byte key")
        self._key = key

    def index(self, plaintext: str | bytes, field_name: str = "") -> SearchableIndex:
        """Generate a deterministic search token for *plaintext*."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        if isinstance(field_name, str):
            field_name = field_name.encode("utf-8")
        # Domain separation: field_name || plaintext
        data = field_name + b"\x00" + plaintext
        token = hmac.new(self._key, data, lambda d=b"": hashlib.blake2b(d, digest_size=32)).digest()
        return SearchableIndex(token=token)

    def encrypt_deterministic(self, plaintext: bytes, field_name: str = "") -> bytes:
        """Deterministic AES-SIV-like encryption (nonce derived from plaintext).

        Not true SIV, but sufficient for equality queries in this design.
        For production, consider AES-SIV (RFC 5297) via a proper library.
        """
        # Derive nonce from plaintext HMAC
        nonce_data = self.index(plaintext, field_name).token[:12]
        aesgcm = AESGCM(self._key)
        # Use a fixed associated data for domain separation
        ad = field_name.encode("utf-8") if field_name else b"det"
        return nonce_data + aesgcm.encrypt(nonce_data, plaintext, ad)

    def decrypt_deterministic(self, ciphertext: bytes, field_name: str = "") -> bytes:
        """Decrypt deterministically encrypted data."""
        if len(ciphertext) < 12:
            raise ValueError("Ciphertext too short")
        nonce = ciphertext[:12]
        payload = ciphertext[12:]
        aesgcm = AESGCM(self._key)
        ad = field_name.encode("utf-8") if field_name else b"det"
        return aesgcm.decrypt(nonce, payload, ad)
