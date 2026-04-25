"""Partial Homomorphic Encryption via Paillier.

Supports additive homomorphic operations on encrypted numbers:
- Enc(a) + Enc(b) = Enc(a + b)
- Enc(a) * n = Enc(a * n)

This allows computing sums and averages on encrypted data without
revealing individual values.
"""

import base64
import json
from dataclasses import dataclass
from typing import Self

from phe import paillier  # type: ignore[import-untyped]

from cryptodb.crypto.envelope import EnvelopeCipher


class HEError(Exception):
    """Base exception for homomorphic encryption errors."""


@dataclass(frozen=True, slots=True)
class HEKeyPair:
    """A Paillier key pair with the private key encrypted under a KEK."""

    public_key_n: int
    encrypted_private_key: bytes  # encrypted under master KEK

    def to_dict(self) -> dict[str, str]:
        return {
            "public_key_n": str(self.public_key_n),
            "encrypted_private_key": base64.b64encode(self.encrypted_private_key).decode(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "HEKeyPair":
        return cls(
            public_key_n=int(data["public_key_n"]),
            encrypted_private_key=base64.b64decode(data["encrypted_private_key"]),
        )


@dataclass(frozen=True, slots=True)
class HEEncryptedNumber:
    """A Paillier-encrypted number serializable to JSON."""

    ciphertext: int
    exponent: int

    def to_dict(self) -> dict[str, int]:
        return {"ciphertext": self.ciphertext, "exponent": self.exponent}

    @classmethod
    def from_dict(cls, data: dict[str, int]) -> "HEEncryptedNumber":
        return cls(ciphertext=data["ciphertext"], exponent=data["exponent"])


class PaillierHE:
    """Wrapper around python-paillier with secure key storage."""

    KEY_SIZE = 2048

    def __init__(self, public_key: paillier.PaillierPublicKey, private_key: paillier.PaillierPrivateKey | None = None) -> None:
        self._public_key = public_key
        self._private_key = private_key

    @classmethod
    def generate_keypair(cls) -> tuple[paillier.PaillierPublicKey, paillier.PaillierPrivateKey]:
        """Generate a new Paillier key pair."""
        pub, priv = paillier.generate_paillier_keypair(n_length=cls.KEY_SIZE)
        return pub, priv

    @classmethod
    def from_public_key(cls, n: int) -> "PaillierHE":
        """Create an instance from a public key modulus."""
        pub = paillier.PaillierPublicKey(n)
        return cls(pub)

    @classmethod
    def from_keypair(cls, pub: paillier.PaillierPublicKey, priv: paillier.PaillierPrivateKey) -> "PaillierHE":
        return cls(pub, priv)

    def encrypt(self, value: int | float) -> HEEncryptedNumber:
        """Encrypt a number."""
        enc = self._public_key.encrypt(value)
        return HEEncryptedNumber(ciphertext=enc.ciphertext(be_secure=False), exponent=enc.exponent)

    def decrypt(self, enc: HEEncryptedNumber) -> int | float:
        """Decrypt an encrypted number."""
        if self._private_key is None:
            raise HEError("Private key not available")
        raw = paillier.EncryptedNumber(self._public_key, enc.ciphertext, enc.exponent)
        return self._private_key.decrypt(raw)

    def add(self, a: HEEncryptedNumber, b: HEEncryptedNumber) -> HEEncryptedNumber:
        """Add two encrypted numbers homomorphically."""
        raw_a = paillier.EncryptedNumber(self._public_key, a.ciphertext, a.exponent)
        raw_b = paillier.EncryptedNumber(self._public_key, b.ciphertext, b.exponent)
        result = raw_a + raw_b
        return HEEncryptedNumber(ciphertext=result.ciphertext(be_secure=False), exponent=result.exponent)

    def add_plain(self, a: HEEncryptedNumber, b: int | float) -> HEEncryptedNumber:
        """Add an encrypted number and a plaintext."""
        raw_a = paillier.EncryptedNumber(self._public_key, a.ciphertext, a.exponent)
        result = raw_a + b
        return HEEncryptedNumber(ciphertext=result.ciphertext(be_secure=False), exponent=result.exponent)

    def multiply_scalar(self, a: HEEncryptedNumber, n: int | float) -> HEEncryptedNumber:
        """Multiply an encrypted number by a plaintext scalar."""
        raw_a = paillier.EncryptedNumber(self._public_key, a.ciphertext, a.exponent)
        result = raw_a * n
        return HEEncryptedNumber(ciphertext=result.ciphertext(be_secure=False), exponent=result.exponent)

    @staticmethod
    def serialize_private_key(priv: paillier.PaillierPrivateKey) -> bytes:
        """Serialize private key to JSON bytes."""
        data = {
            "p": priv.p,
            "q": priv.q,
        }
        return json.dumps(data).encode("utf-8")

    @staticmethod
    def deserialize_private_key(pub: paillier.PaillierPublicKey, data: bytes) -> paillier.PaillierPrivateKey:
        """Deserialize private key from JSON bytes."""
        obj = json.loads(data)
        return paillier.PaillierPrivateKey(pub, int(obj["p"]), int(obj["q"]))

    def has_private_key(self) -> bool:
        return self._private_key is not None
