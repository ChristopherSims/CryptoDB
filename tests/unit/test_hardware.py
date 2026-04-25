"""Unit tests for hardware token integration (FIDO2 + TPM)."""

import base64
import hashlib

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.auth.hardware import (
    FIDO2Credential,
    HardwareTokenManager,
    TPMBackend,
)
from cryptodb.auth.mfa import MFAChallengeStore, get_mfa_store
from cryptodb.auth.users import create_user
from cryptodb.config import settings
from cryptodb.db.connection import AsyncSessionLocal, init_db


@pytest.fixture(autouse=True)
def temp_dirs():
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        settings.data_dir = os.path.join(tmpdir, "data")
        settings.blob_dir = os.path.join(tmpdir, "data", "blobs")
        settings.db_path = os.path.join(tmpdir, "data", "cryptodb.db")
        settings.keys_dir = os.path.join(tmpdir, "data", "keys")
        yield


@pytest.fixture
async def session():
    await init_db()
    async with AsyncSessionLocal() as s:
        yield s
        await s.rollback()


@pytest.fixture
async def admin(session: AsyncSession):
    return await create_user(session, "admin", "adminpass", role="admin")


class TestTPMBackend:
    def test_software_fallback_seal_unseal(self) -> None:
        tpm = TPMBackend(use_software_fallback=True)
        assert tpm.is_available()
        data = b"super secret master key"
        sealed = tpm.seal(data)
        assert sealed.startswith(b"SOFT")
        unsealed = tpm.unseal(sealed)
        assert unsealed == data

    def test_software_fallback_tamper_detected(self) -> None:
        tpm = TPMBackend(use_software_fallback=True)
        data = b"super secret master key"
        sealed = tpm.seal(data)
        # Tamper with the sealed blob
        tampered = sealed[:4] + b"\x00" * (len(sealed) - 4)
        with pytest.raises(ValueError):
            tpm.unseal(tampered)

    def test_invalid_blob_prefix(self) -> None:
        tpm = TPMBackend(use_software_fallback=True)
        with pytest.raises(ValueError, match="Invalid software sealed blob"):
            tpm.unseal(b"UNKNOWN")


class TestFIDO2Credential:
    def test_roundtrip_dict(self) -> None:
        cred = FIDO2Credential(
            credential_id=b"cred-id-123",
            public_key=b"pub-key-456",
            sign_count=5,
            name="My YubiKey",
        )
        d = cred.to_dict()
        restored = FIDO2Credential.from_dict(d)
        assert restored.credential_id == cred.credential_id
        assert restored.public_key == cred.public_key
        assert restored.sign_count == cred.sign_count
        assert restored.name == cred.name


class TestHardwareTokenManager:
    async def test_save_and_get_credentials(self, session: AsyncSession, admin) -> None:
        mgr = HardwareTokenManager()
        cred = FIDO2Credential(
            credential_id=b"test-cred",
            public_key=b"test-pub",
            sign_count=0,
            name="Test Token",
        )
        row = await mgr.save_credential(session, admin.id, cred)
        await session.commit()

        fetched = await mgr.get_credentials(session, admin.id)
        assert len(fetched) == 1
        assert fetched[0].credential_id == b"test-cred"
        assert fetched[0].name == "Test Token"

    async def test_update_sign_count(self, session: AsyncSession, admin) -> None:
        mgr = HardwareTokenManager()
        cred = FIDO2Credential(
            credential_id=b"test-cred",
            public_key=b"test-pub",
            sign_count=0,
            name="Test Token",
        )
        await mgr.save_credential(session, admin.id, cred)
        await session.commit()

        updated = FIDO2Credential(
            credential_id=b"test-cred",
            public_key=b"test-pub",
            sign_count=42,
            name="Test Token",
        )
        await mgr.update_sign_count(session, admin.id, updated)
        await session.commit()

        fetched = await mgr.get_credentials(session, admin.id)
        assert fetched[0].sign_count == 42

    def test_tpm_seal_unseal(self) -> None:
        mgr = HardwareTokenManager()
        data = b"master-key-material"
        sealed = mgr.tpm_seal(data)
        unsealed = mgr.tpm_unseal(sealed)
        assert unsealed == data


class TestMFAChallengeStore:
    def test_create_and_get(self) -> None:
        store = MFAChallengeStore()
        token = store.create("user-1", "fido2", {"challenge": "abc"})
        challenge = store.get(token)
        assert challenge is not None
        assert challenge.user_id == "user-1"
        assert challenge.challenge_type == "fido2"

    def test_expired_challenge(self) -> None:
        store = MFAChallengeStore()
        token = store.create("user-1", "fido2", {"challenge": "abc"})
        # Manually expire
        challenge = store.get(token)
        challenge.created_at = 0  # type: ignore[assignment]
        assert store.get(token) is None

    def test_remove(self) -> None:
        store = MFAChallengeStore()
        token = store.create("user-1", "fido2", {"challenge": "abc"})
        store.remove(token)
        assert store.get(token) is None

    def test_singleton(self) -> None:
        store1 = get_mfa_store()
        store2 = get_mfa_store()
        assert store1 is store2
