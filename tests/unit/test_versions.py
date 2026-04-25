"""Tests for record versioning helpers."""

from datetime import datetime, timezone

import pytest

from cryptodb.db.versions import VersionInfo, bump_version


class TestBumpVersion:
    def test_bumps(self):
        assert bump_version(1) == 2
        assert bump_version(0) == 1
        assert bump_version(99) == 100


class TestVersionInfo:
    def test_creation(self):
        now = datetime.now(timezone.utc)
        v = VersionInfo(
            version=1,
            record_id="r1",
            previous_version_id=None,
            created_at=now,
            size_bytes=100,
        )
        assert v.version == 1
        assert v.record_id == "r1"
        assert v.previous_version_id is None
        assert v.size_bytes == 100

    def test_frozen(self):
        now = datetime.now(timezone.utc)
        v = VersionInfo(version=1, record_id="r1", previous_version_id=None, created_at=now, size_bytes=100)
        with pytest.raises(AttributeError):
            v.version = 2
