"""Data integrity via HMAC-SHA3-256 over ciphertext."""

import base64
import hmac
from dataclasses import dataclass
from hashlib import sha3_256


@dataclass(frozen=True, slots=True)
class IntegrityToken:
    """HMAC digest and metadata for integrity verification."""

    digest: bytes
    algorithm: str = "hmac-sha3-256"

    def to_dict(self) -> dict[str, str]:
        return {
            "digest": base64.b64encode(self.digest).decode(),
            "algorithm": self.algorithm,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "IntegrityToken":
        return cls(
            digest=base64.b64decode(data["digest"]),
            algorithm=data.get("algorithm", "hmac-sha3-256"),
        )


def compute_hmac(data: bytes, key: bytes) -> IntegrityToken:
    """Compute HMAC-SHA3-256 over *data*."""
    digest = hmac.new(key, data, sha3_256).digest()
    return IntegrityToken(digest=digest)


def verify_hmac(data: bytes, token: IntegrityToken, key: bytes) -> bool:
    """Verify HMAC in constant time."""
    expected = compute_hmac(data, key)
    return hmac.compare_digest(expected.digest, token.digest)
