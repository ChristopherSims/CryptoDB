"""Hardware token integration: YubiKey (FIDO2/WebAuthn) and TPM key sealing."""

import base64
import hashlib
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.db.metadata import HardwareTokenCredential, User

logger = logging.getLogger(__name__)

# Optional TPM import with graceful fallback
try:
    from tpm2_pytss import ESAPI, TPM2B_SENSITIVE_CREATE, TPM2B_PUBLIC
    _TPM_AVAILABLE = True
except Exception:
    _TPM_AVAILABLE = False

# Optional fido2 import
try:
    from fido2.server import Fido2Server
    from fido2.webauthn import AttestedCredentialData, PublicKeyCredentialDescriptor
    _FIDO2_AVAILABLE = True
except Exception:
    _FIDO2_AVAILABLE = False


@dataclass(frozen=True)
class FIDO2Credential:
    """Serializable FIDO2 credential."""

    credential_id: bytes
    public_key: bytes
    sign_count: int = 0
    name: str = "Primary Token"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": base64.urlsafe_b64encode(self.credential_id).decode().rstrip("="),
            "publicKey": base64.urlsafe_b64encode(self.public_key).decode().rstrip("="),
            "signCount": self.sign_count,
            "name": self.name,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "FIDO2Credential":
        def _b64decode(s: str) -> bytes:
            pad = 4 - len(s) % 4
            if pad != 4:
                s += "=" * pad
            return base64.urlsafe_b64decode(s)

        return cls(
            credential_id=_b64decode(d["id"]),
            public_key=_b64decode(d["publicKey"]),
            sign_count=d.get("signCount", 0),
            name=d.get("name", "Primary Token"),
        )


class HardwareTokenBackend(ABC):
    """Abstract base for hardware token operations."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the backend hardware is present."""
        ...


class FIDO2Backend(HardwareTokenBackend):
    """FIDO2/WebAuthn server-side logic for YubiKey and other authenticators."""

    def __init__(self, rp_id: str = "cryptodb.local", rp_name: str = "CryptoDB") -> None:
        if not _FIDO2_AVAILABLE:
            raise RuntimeError("fido2 library not installed")
        self._server = Fido2Server({"id": rp_id, "name": rp_name})
        self._rp_id = rp_id

    def is_available(self) -> bool:
        return _FIDO2_AVAILABLE

    def register_begin(
        self,
        user: User,
        existing_credentials: list[FIDO2Credential] | None = None,
    ) -> tuple[dict, dict]:
        """Generate a registration challenge. Returns (public_credential_options, state)."""
        exclude_credentials = None
        if existing_credentials:
            exclude_credentials = [
                {"id": cred.credential_id, "type": "public-key"}
                for cred in existing_credentials
            ]

        registration_data, state = self._server.register_begin(
            {
                "id": user.id.encode(),
                "name": user.username,
                "displayName": user.username,
            },
            credentials=exclude_credentials or [],
            user_verification="discouraged",
            authenticator_attachment=None,
        )
        # registration_data is a dict that can be JSON-serialized
        return registration_data, state

    def register_end(
        self,
        state: dict,
        client_response: dict,
    ) -> FIDO2Credential:
        """Verify a registration response and return the credential."""
        auth_data = self._server.register_end(state, client_response)
        return FIDO2Credential(
            credential_id=auth_data.credential_data.credential_id,
            public_key=auth_data.credential_data.public_key,
            sign_count=auth_data.credential_data.sign_count,
        )

    def authenticate_begin(
        self,
        credentials: list[FIDO2Credential],
    ) -> tuple[dict, dict]:
        """Generate an authentication challenge. Returns (public_request_options, state)."""
        creds = [
            {"id": cred.credential_id, "type": "public-key"}
            for cred in credentials
        ]
        auth_data, state = self._server.authenticate_begin(creds)
        return auth_data, state

    def authenticate_end(
        self,
        state: dict,
        credentials: list[FIDO2Credential],
        client_response: dict,
    ) -> FIDO2Credential:
        """Verify an authentication response. Returns the matched credential with updated sign_count."""
        # Build attested credential data list for fido2
        cred_map = {c.credential_id: c for c in credentials}
        cred_list = [
            AttestedCredentialData.create(c.credential_id, c.public_key)
            for c in credentials
        ]
        auth_data = self._server.authenticate_end(state, cred_list, client_response)
        matched = cred_map.get(auth_data.credential_id)
        if matched is None:
            raise ValueError("Unknown credential")
        return FIDO2Credential(
            credential_id=matched.credential_id,
            public_key=matched.public_key,
            sign_count=auth_data.counter,
            name=matched.name,
        )


class TPMBackend(HardwareTokenBackend):
    """TPM key sealing backend. Falls back to software simulation if TPM unavailable."""

    def __init__(self, use_software_fallback: bool = True) -> None:
        self._esapi = None
        self._fallback = False
        if _TPM_AVAILABLE:
            try:
                self._esapi = ESAPI()
            except Exception as exc:
                logger.warning("TPM not accessible: %s", exc)
                if not use_software_fallback:
                    raise
                self._fallback = True
        else:
            if not use_software_fallback:
                raise RuntimeError("tpm2-pytss not installed and fallback disabled")
            self._fallback = True

    def is_available(self) -> bool:
        return self._esapi is not None or self._fallback

    def seal(self, data: bytes, policy_digest: bytes | None = None) -> bytes:
        """Seal *data* to the TPM (or software fallback). Returns sealed blob."""
        if self._esapi is not None:
            return self._tpm_seal(data, policy_digest)
        return self._software_seal(data)

    def unseal(self, sealed_blob: bytes) -> bytes:
        """Unseal data from the TPM (or software fallback)."""
        if self._esapi is not None:
            return self._tpm_unseal(sealed_blob)
        return self._software_unseal(sealed_blob)

    def _tpm_seal(self, data: bytes, policy_digest: bytes | None = None) -> bytes:
        # Simplified TPM seal using ESAPI
        # In production, proper auth, PCR policies, and handles are needed
        in_sensitive = TPM2B_SENSITIVE_CREATE()
        # Create a sealed data object
        # This is a high-level approximation; real TPM code is more involved
        import tpm2_pytss.constants as tpm_const
        template = TPM2B_PUBLIC.parse(
            "rsa:2048",
            attrs=tpm_const.TPMA_OBJECT.USERWITHAUTH
            | tpm_const.TPMA_OBJECT.SIGN_ENCRYPT
            | tpm_const.TPMA_OBJECT.FIXEDTPM
            | tpm_const.TPMA_OBJECT.FIXEDPARENT,
        )
        handle, _, _, _, _ = self._esapi.create_primary(
            tpm_const.TPM2_RH_OWNER, in_sensitive, template
        )
        # For simplicity, we use AES-256-GCM with a key derived from the TPM primary
        # Real implementation would use TPM2_Seal/TPM2_Unseal
        derived = self._derive_from_tpm(handle, len(data) + 32)
        nonce = derived[:12]
        key = derived[12:44]
        from cryptodb.crypto.ciphers import AES256GCM
        aes = AES256GCM(key)
        ciphertext = aes.encrypt(data)
        self._esapi.flush_context(handle)
        # Prepend nonce + TPM marker
        return b"TPM1" + nonce + ciphertext

    def _tpm_unseal(self, sealed_blob: bytes) -> bytes:
        if not sealed_blob.startswith(b"TPM1"):
            raise ValueError("Invalid TPM sealed blob")
        import tpm2_pytss.constants as tpm_const
        in_sensitive = TPM2B_SENSITIVE_CREATE()
        template = TPM2B_PUBLIC.parse(
            "rsa:2048",
            attrs=tpm_const.TPMA_OBJECT.USERWITHAUTH
            | tpm_const.TPMA_OBJECT.SIGN_ENCRYPT
            | tpm_const.TPMA_OBJECT.FIXEDTPM
            | tpm_const.TPMA_OBJECT.FIXEDPARENT,
        )
        handle, _, _, _, _ = self._esapi.create_primary(
            tpm_const.TPM2_RH_OWNER, in_sensitive, template
        )
        nonce = sealed_blob[4:16]
        ciphertext = sealed_blob[16:]
        derived = self._derive_from_tpm(handle, len(ciphertext) + 32)
        key = derived[12:44]
        from cryptodb.crypto.ciphers import AES256GCM
        aes = AES256GCM(key)
        plaintext = aes.decrypt(ciphertext)
        self._esapi.flush_context(handle)
        return plaintext

    def _derive_from_tpm(self, handle: Any, length: int) -> bytes:
        # Derive pseudo-random bytes deterministically from a TPM handle
        # In a real implementation, this uses TPM2_GetRandom or KDF
        handle_bytes = str(handle).encode()
        return hashlib.sha3_256(handle_bytes).digest()[:length]

    def _software_seal(self, data: bytes) -> bytes:
        """Software fallback: encrypt data with a key derived from machine fingerprint."""
        fingerprint = self._machine_fingerprint()
        key = hashlib.sha3_256(fingerprint).digest()
        from cryptodb.crypto.ciphers import AES256GCM
        aes = AES256GCM(key)
        ciphertext = aes.encrypt(data)
        return b"SOFT" + ciphertext

    def _software_unseal(self, sealed_blob: bytes) -> bytes:
        if not sealed_blob.startswith(b"SOFT"):
            raise ValueError("Invalid software sealed blob")
        fingerprint = self._machine_fingerprint()
        key = hashlib.sha3_256(fingerprint).digest()
        ciphertext = sealed_blob[4:]
        from cryptodb.crypto.ciphers import AES256GCM
        from cryptography.exceptions import InvalidTag
        aes = AES256GCM(key)
        try:
            return aes.decrypt(ciphertext)
        except InvalidTag:
            raise ValueError("Tampered or invalid sealed blob") from None

    @staticmethod
    def _machine_fingerprint() -> bytes:
        """Derive a machine-specific fingerprint for software fallback sealing."""
        parts = [
            os.environ.get("HOSTNAME", "").encode(),
            os.environ.get("COMPUTERNAME", "").encode(),
        ]
        # Try to read /etc/machine-id
        try:
            with open("/etc/machine-id", "rb") as f:
                parts.append(f.read().strip())
        except FileNotFoundError:
            pass
        return hashlib.sha3_256(b"|".join(parts)).digest()


class HardwareTokenManager:
    """High-level manager for hardware token credentials and TPM sealing."""

    def __init__(self, rp_id: str = "cryptodb.local", rp_name: str = "CryptoDB") -> None:
        self._fido2 = FIDO2Backend(rp_id, rp_name) if _FIDO2_AVAILABLE else None
        self._tpm = TPMBackend(use_software_fallback=True)

    # ------------------------------------------------------------------
    # FIDO2 credential persistence
    # ------------------------------------------------------------------

    async def get_credentials(self, session: AsyncSession, user_id: str) -> list[FIDO2Credential]:
        result = await session.execute(
            select(HardwareTokenCredential).where(
                HardwareTokenCredential.user_id == user_id,
                HardwareTokenCredential.token_type == "fido2",
            )
        )
        rows = result.scalars().all()

        def _b64decode_padded(s: str) -> bytes:
            padding = 4 - len(s) % 4
            if padding != 4:
                s += "=" * padding
            return base64.urlsafe_b64decode(s)

        return [
            FIDO2Credential(
                credential_id=_b64decode_padded(row.credential_id),
                public_key=_b64decode_padded(row.public_key),
                sign_count=row.sign_count,
                name=row.name,
            )
            for row in rows
        ]

    async def save_credential(
        self,
        session: AsyncSession,
        user_id: str,
        credential: FIDO2Credential,
    ) -> HardwareTokenCredential:
        row = HardwareTokenCredential(
            user_id=user_id,
            credential_id=base64.urlsafe_b64encode(credential.credential_id).decode().rstrip("="),
            public_key=base64.urlsafe_b64encode(credential.public_key).decode().rstrip("="),
            token_type="fido2",
            sign_count=credential.sign_count,
            name=credential.name,
        )
        session.add(row)
        await session.flush()
        return row

    async def update_sign_count(
        self,
        session: AsyncSession,
        user_id: str,
        credential: FIDO2Credential,
    ) -> None:
        credential_id_b64 = base64.urlsafe_b64encode(credential.credential_id).decode().rstrip("=")
        result = await session.execute(
            select(HardwareTokenCredential).where(
                HardwareTokenCredential.user_id == user_id,
                HardwareTokenCredential.credential_id == credential_id_b64,
            )
        )
        row = result.scalar_one_or_none()
        if row is not None:
            row.sign_count = credential.sign_count
            row.last_used_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
            await session.flush()

    # ------------------------------------------------------------------
    # FIDO2 flows
    # ------------------------------------------------------------------

    def fido2_available(self) -> bool:
        return self._fido2 is not None

    def register_begin(
        self,
        user: User,
        existing_credentials: list[FIDO2Credential] | None = None,
    ) -> tuple[dict, dict]:
        if self._fido2 is None:
            raise RuntimeError("FIDO2 not available")
        return self._fido2.register_begin(user, existing_credentials)

    def register_end(self, state: dict, client_response: dict) -> FIDO2Credential:
        if self._fido2 is None:
            raise RuntimeError("FIDO2 not available")
        return self._fido2.register_end(state, client_response)

    def authenticate_begin(self, credentials: list[FIDO2Credential]) -> tuple[dict, dict]:
        if self._fido2 is None:
            raise RuntimeError("FIDO2 not available")
        return self._fido2.authenticate_begin(credentials)

    def authenticate_end(
        self,
        state: dict,
        credentials: list[FIDO2Credential],
        client_response: dict,
    ) -> FIDO2Credential:
        if self._fido2 is None:
            raise RuntimeError("FIDO2 not available")
        return self._fido2.authenticate_end(state, credentials, client_response)

    # ------------------------------------------------------------------
    # TPM flows
    # ------------------------------------------------------------------

    def tpm_available(self) -> bool:
        return self._tpm.is_available()

    def tpm_seal(self, data: bytes) -> bytes:
        return self._tpm.seal(data)

    def tpm_unseal(self, sealed_blob: bytes) -> bytes:
        return self._tpm.unseal(sealed_blob)
