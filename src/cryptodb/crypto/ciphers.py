"""Low-level symmetric cipher primitives."""

import os
from abc import ABC, abstractmethod
from typing import Self

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, XChaCha20Poly1305


class Cipher(ABC):
    """Abstract base for AEAD ciphers."""

    @abstractmethod
    def encrypt(self, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
        """Encrypt plaintext; return nonce + ciphertext + tag."""

    @abstractmethod
    def decrypt(self, ciphertext: bytes, associated_data: bytes | None = None) -> bytes:
        """Decrypt ciphertext; verify tag."""

    @classmethod
    @abstractmethod
    def generate_key(cls) -> bytes:
        """Generate a new random key suitable for this cipher."""

    @classmethod
    @abstractmethod
    def from_key(cls, key: bytes) -> Self:
        """Instantiate from a key."""


class AES256GCM(Cipher):
    """AES-256-GCM via PyCA cryptography."""

    NONCE_SIZE = 12
    KEY_SIZE = 32

    def __init__(self, key: bytes) -> None:
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"AES-256-GCM requires a {self.KEY_SIZE}-byte key")
        self._aead = AESGCM(key)

    @classmethod
    def generate_key(cls) -> bytes:
        return os.urandom(cls.KEY_SIZE)

    @classmethod
    def from_key(cls, key: bytes) -> Self:
        return cls(key)

    def encrypt(self, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
        nonce = os.urandom(self.NONCE_SIZE)
        return nonce + self._aead.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, ciphertext: bytes, associated_data: bytes | None = None) -> bytes:
        if len(ciphertext) < self.NONCE_SIZE:
            raise ValueError("Ciphertext too short")
        nonce = ciphertext[: self.NONCE_SIZE]
        payload = ciphertext[self.NONCE_SIZE :]
        return self._aead.decrypt(nonce, payload, associated_data)


class XChaCha20Poly1305Cipher(Cipher):
    """XChaCha20-Poly1305 via PyCA cryptography."""

    NONCE_SIZE = 24
    KEY_SIZE = 32

    def __init__(self, key: bytes) -> None:
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"XChaCha20-Poly1305 requires a {self.KEY_SIZE}-byte key")
        self._aead = XChaCha20Poly1305(key)

    @classmethod
    def generate_key(cls) -> bytes:
        return os.urandom(cls.KEY_SIZE)

    @classmethod
    def from_key(cls, key: bytes) -> Self:
        return cls(key)

    def encrypt(self, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
        nonce = os.urandom(self.NONCE_SIZE)
        return nonce + self._aead.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, ciphertext: bytes, associated_data: bytes | None = None) -> bytes:
        if len(ciphertext) < self.NONCE_SIZE:
            raise ValueError("Ciphertext too short")
        nonce = ciphertext[: self.NONCE_SIZE]
        payload = ciphertext[self.NONCE_SIZE :]
        return self._aead.decrypt(nonce, payload, associated_data)


def cipher_factory(name: str, key: bytes) -> Cipher:
    """Return a Cipher instance by name."""
    match name.lower():
        case "aes-256-gcm":
            return AES256GCM.from_key(key)
        case "xchacha20-poly1305":
            return XChaCha20Poly1305Cipher.from_key(key)
        case _:
            raise ValueError(f"Unknown cipher: {name}")
