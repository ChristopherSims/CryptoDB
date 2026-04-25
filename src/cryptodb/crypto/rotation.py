"""Key rotation logic: re-encrypt DEKs under a new master key."""

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.config import settings
from cryptodb.crypto.envelope import Envelope, EnvelopeCipher
from cryptodb.db.metadata import Record
from cryptodb.exceptions import KeyManagementError, ConfigurationError


class RotationError(Exception):
    """Base exception for rotation failures."""


class RotationSchedulerError(Exception):
    """Base exception for scheduler failures."""


def rotate_dek(envelope: Envelope, old_cipher: EnvelopeCipher, new_cipher: EnvelopeCipher) -> Envelope:
    """Re-wrap an envelope's DEK under a new master key.

    The data itself is not touched; only the DEK is decrypted with the old
    master key and re-encrypted with the new master key.
    """
    # Decrypt DEK using old master key
    dek = old_cipher._unwrap_dek(envelope.encrypted_dek)
    try:
        # Re-wrap DEK with new master key
        new_edek = new_cipher._wrap_dek(dek)
    finally:
        dek = bytes(len(dek))

    return Envelope(
        encrypted_dek=new_edek,
        ciphertext=envelope.ciphertext,
        cipher_name=envelope.cipher_name,
        record_id=envelope.record_id,
    )


@dataclass
class RotationState:
    """Persisted state for key rotation scheduling."""

    last_rotation: datetime | None = None
    current_key_id: str | None = None
    auto_rotate: bool = False
    interval_hours: int = 168  # 7 days

    def to_dict(self) -> dict:
        return {
            "last_rotation": self.last_rotation.isoformat() if self.last_rotation else None,
            "current_key_id": self.current_key_id,
            "auto_rotate": self.auto_rotate,
            "interval_hours": self.interval_hours,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RotationState":
        last = data.get("last_rotation")
        return cls(
            last_rotation=datetime.fromisoformat(last) if last else None,
            current_key_id=data.get("current_key_id"),
            auto_rotate=data.get("auto_rotate", False),
            interval_hours=data.get("interval_hours", 168),
        )


class RotationScheduler:
    """Schedules and executes master key rotation.

    Maintains a small JSON state file to track when the last rotation
    occurred and whether auto-rotation is enabled.
    """

    def __init__(self, state_path: Path | None = None) -> None:
        self._state_path = state_path or (settings.resolved_data_dir / "rotation_state.json")
        self._state = self._load_state()

    def _load_state(self) -> RotationState:
        if self._state_path.exists():
            try:
                data = json.loads(self._state_path.read_text())
                return RotationState.from_dict(data)
            except (json.JSONDecodeError, KeyError, TypeError):
                pass
        return RotationState(
            current_key_id=settings.master_key_id,
            auto_rotate=settings.key_rotation_interval_hours > 0,
            interval_hours=settings.key_rotation_interval_hours or 168,
        )

    def _save_state(self) -> None:
        self._state_path.write_text(json.dumps(self._state.to_dict(), indent=2))

    def should_rotate(self) -> bool:
        """Return True if enough time has elapsed since the last rotation."""
        if not self._state.auto_rotate or not self._state.last_rotation:
            return False
        elapsed = (datetime.now(timezone.utc) - self._state.last_rotation).total_seconds()
        return elapsed >= self._state.interval_hours * 3600

    def get_next_rotation(self) -> datetime | None:
        """Return the next scheduled rotation time, or None."""
        if not self._state.auto_rotate or not self._state.last_rotation:
            return None
        return self._state.last_rotation.replace(tzinfo=timezone.utc) + timedelta(hours=self._state.interval_hours)

    def configure(self, auto_rotate: bool | None = None, interval_hours: int | None = None) -> None:
        """Update scheduler configuration."""
        if auto_rotate is not None:
            self._state.auto_rotate = auto_rotate
        if interval_hours is not None:
            self._state.interval_hours = interval_hours
        self._save_state()

    async def rotate_all_records(
        self,
        session: AsyncSession,
        old_cipher: EnvelopeCipher,
        new_cipher: EnvelopeCipher,
        new_key_id: str,
    ) -> int:
        """Re-encrypt DEKs for all active records.

        Returns the number of records rotated.
        """
        result = await session.execute(
            select(Record).where(Record.is_deleted == False)  # noqa: E712
        )
        records = result.scalars().all()
        rotated = 0
        for record in records:
            from cryptodb.crypto.envelope import EncryptedDataKey

            envelope = Envelope(
                encrypted_dek=EncryptedDataKey.from_dict(record.encrypted_dek),
                ciphertext=b"",  # ciphertext not needed for DEK rotation
                cipher_name=record.cipher_name,
                record_id=record.id,
            )
            new_envelope = rotate_dek(envelope, old_cipher, new_cipher)
            record.encrypted_dek = new_envelope.encrypted_dek.to_dict()
            record.master_key_id = new_key_id
            # Re-compute integrity token over the *same* ciphertext with new key? No,
            # integrity is over ciphertext which hasn't changed. However if we change
            # integ_key with the master key, old records would fail. For now we keep
            # integrity as-is since the ciphertext blob is unchanged.
            rotated += 1
            if rotated % 100 == 0:
                await session.flush()
        await session.flush()
        self._state.last_rotation = datetime.now(timezone.utc)
        self._state.current_key_id = new_key_id
        self._save_state()
        return rotated

    async def run_auto_rotation(
        self,
        session: AsyncSession,
        ks: "MasterKeyStore",
        passphrase: str,
    ) -> str:
        """Execute a full auto-rotation cycle if due.

        Creates a new master key, re-encrypts all records, and retires the old key.
        Returns the new key ID.
        """
        if not self.should_rotate():
            raise RotationSchedulerError("Rotation not due yet")

        old_key_id = self._state.current_key_id or settings.master_key_id
        old_key = ks.load_master_key(passphrase, old_key_id)
        old_cipher = EnvelopeCipher(old_key)

        # Generate new key with a timestamped ID
        new_key_id = f"{settings.master_key_id}-v{int(datetime.now(timezone.utc).timestamp())}"
        new_key = ks.create_master_key(passphrase, new_key_id)
        new_cipher = EnvelopeCipher(new_key)

        rotated = await self.rotate_all_records(session, old_cipher, new_cipher, new_key_id)

        # Update settings and active key
        settings.master_key_id = new_key_id
        self._state.current_key_id = new_key_id
        self._save_state()

        return new_key_id
