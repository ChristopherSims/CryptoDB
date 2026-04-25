"""Unit tests for key rotation scheduler."""

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cryptodb.crypto.envelope import EnvelopeCipher
from cryptodb.crypto.rotation import (
    RotationScheduler,
    RotationState,
    rotate_dek,
)
from cryptodb.exceptions import ConfigurationError


class TestRotateDek:
    def test_rewrap_dek(self) -> None:
        old_key = b"a" * 32
        new_key = b"b" * 32
        old_cipher = EnvelopeCipher(old_key)
        new_cipher = EnvelopeCipher(new_key)
        envelope = old_cipher.encrypt(b"plaintext data")
        new_envelope = rotate_dek(envelope, old_cipher, new_cipher)
        assert new_envelope.ciphertext == envelope.ciphertext
        assert new_envelope.cipher_name == envelope.cipher_name
        # New envelope should decrypt with new key
        decrypted = new_cipher.decrypt(new_envelope)
        assert decrypted == b"plaintext data"


class TestRotationState:
    def test_serialization(self) -> None:
        now = datetime.now(timezone.utc)
        state = RotationState(
            last_rotation=now,
            current_key_id="key-v2",
            auto_rotate=True,
            interval_hours=48,
        )
        data = state.to_dict()
        restored = RotationState.from_dict(data)
        assert restored.last_rotation == now
        assert restored.current_key_id == "key-v2"
        assert restored.auto_rotate is True
        assert restored.interval_hours == 48

    def test_from_dict_none_last_rotation(self) -> None:
        state = RotationState.from_dict({"last_rotation": None, "current_key_id": "k1"})
        assert state.last_rotation is None
        assert state.current_key_id == "k1"


class TestRotationScheduler:
    def test_should_rotate_when_due(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state = RotationState(
                last_rotation=datetime.now(timezone.utc) - timedelta(hours=25),
                auto_rotate=True,
                interval_hours=24,
            )
            state_path.write_text(json.dumps(state.to_dict()))
            scheduler = RotationScheduler(state_path=state_path)
            assert scheduler.should_rotate() is True

    def test_should_not_rotate_when_not_due(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state = RotationState(
                last_rotation=datetime.now(timezone.utc) - timedelta(hours=1),
                auto_rotate=True,
                interval_hours=24,
            )
            state_path.write_text(json.dumps(state.to_dict()))
            scheduler = RotationScheduler(state_path=state_path)
            assert scheduler.should_rotate() is False

    def test_should_not_rotate_when_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state = RotationState(
                last_rotation=datetime.now(timezone.utc) - timedelta(hours=100),
                auto_rotate=False,
                interval_hours=24,
            )
            state_path.write_text(json.dumps(state.to_dict()))
            scheduler = RotationScheduler(state_path=state_path)
            assert scheduler.should_rotate() is False

    def test_configure(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            scheduler = RotationScheduler(state_path=state_path)
            scheduler.configure(auto_rotate=True, interval_hours=72)
            assert scheduler._state.auto_rotate is True
            assert scheduler._state.interval_hours == 72
            # Verify persistence
            scheduler2 = RotationScheduler(state_path=state_path)
            assert scheduler2._state.auto_rotate is True
            assert scheduler2._state.interval_hours == 72

    def test_get_next_rotation(self) -> None:
        last = datetime.now(timezone.utc) - timedelta(hours=10)
        state = RotationState(
            last_rotation=last,
            auto_rotate=True,
            interval_hours=24,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state_path.write_text(json.dumps(state.to_dict()))
            scheduler = RotationScheduler(state_path=state_path)
            next_rot = scheduler.get_next_rotation()
            assert next_rot is not None
            expected = last + timedelta(hours=24)
            assert abs((next_rot - expected).total_seconds()) < 1
