"""Envelope encryption: KEK protects DEK, DEK protects data."""

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptodb.config import settings
from cryptodb.crypto.ciphers import AES256GCM, Cipher, XChaCha20Poly1305Cipher, _XCHACHA_AVAILABLE


@dataclass(frozen=True, slots=True)
class EncryptedDataKey:
    """A DEK encrypted under the master KEK."""

    ciphertext: bytes
    iv: bytes
    algorithm: str  # e.g. "aes-256-gcm-wrap"

    def to_dict(self) -> dict[str, str]:
        return {
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
            "iv": base64.b64encode(self.iv).decode(),
            "algorithm": self.algorithm,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "EncryptedDataKey":
        return cls(
            ciphertext=base64.b64decode(data["ciphertext"]),
            iv=base64.b64decode(data["iv"]),
            algorithm=data["algorithm"],
        )


@dataclass(frozen=True, slots=True)
class Envelope:
    """The full encrypted envelope for a record."""

    encrypted_dek: EncryptedDataKey
    ciphertext: bytes
    cipher_name: str
    record_id: str | None = None

    def to_dict(self) -> dict[str, str]:
        return {
            "encrypted_dek": self.encrypted_dek.to_dict(),
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
            "cipher_name": self.cipher_name,
            "record_id": self.record_id or "",
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "Envelope":
        return cls(
            encrypted_dek=EncryptedDataKey.from_dict(data["encrypted_dek"]),
            ciphertext=base64.b64decode(data["ciphertext"]),
            cipher_name=data["cipher_name"],
            record_id=data.get("record_id") or None,
        )


class EnvelopeCipher:
    """Handles envelope encryption using a master KEK."""

    WRAP_CIPHER = "aes-256-gcm-wrap"

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) not in (16, 24, 32):
            raise ValueError("Master key must be 16, 24, or 32 bytes")
        self._master_key = master_key

    def _wrap_dek(self, dek: bytes) -> EncryptedDataKey:
        iv = os.urandom(12)
        wrapper = AESGCM(self._master_key)
        ct = wrapper.encrypt(iv, dek, None)
        return EncryptedDataKey(ciphertext=ct, iv=iv, algorithm=self.WRAP_CIPHER)

    def _unwrap_dek(self, edek: EncryptedDataKey) -> bytes:
        wrapper = AESGCM(self._master_key)
        return wrapper.decrypt(edek.iv, edek.ciphertext, None)

    def encrypt(
        self, plaintext: bytes, cipher_name: str | None = None, record_id: str | None = None
    ) -> Envelope:
        """Encrypt *plaintext* under a freshly generated DEK."""
        cipher_name = cipher_name or settings.default_cipher
        # Generate key via classmethod without instantiating
        if cipher_name.lower() == "aes-256-gcm":
            dek = AES256GCM.generate_key()
            cipher: Cipher = AES256GCM(dek)
        elif cipher_name.lower() == "xchacha20-poly1305":
            if not _XCHACHA_AVAILABLE:
                raise RuntimeError("XChaCha20Poly1305 not available")
            dek = XChaCha20Poly1305Cipher.generate_key()
            cipher = XChaCha20Poly1305Cipher(dek)
        else:
            raise ValueError(f"Unknown cipher: {cipher_name}")
        ciphertext = cipher.encrypt(plaintext)
        edek = self._wrap_dek(dek)
        # Securely clear DEK from memory (best effort)
        dek = bytes(len(dek))
        return Envelope(
            encrypted_dek=edek,
            ciphertext=ciphertext,
            cipher_name=cipher_name,
            record_id=record_id,
        )

    def decrypt(self, envelope: Envelope) -> bytes:
        """Decrypt an envelope."""
        dek = self._unwrap_dek(envelope.encrypted_dek)
        try:
            if envelope.cipher_name.lower() == "aes-256-gcm":
                cipher: Cipher = AES256GCM(dek)
            elif envelope.cipher_name.lower() == "xchacha20-poly1305":
                cipher = XChaCha20Poly1305Cipher(dek)
            else:
                raise ValueError(f"Unknown cipher: {envelope.cipher_name}")
            return cipher.decrypt(envelope.ciphertext)
        finally:
            dek = bytes(len(dek))
