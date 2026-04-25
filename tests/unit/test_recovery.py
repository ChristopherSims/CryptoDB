"""Unit tests for Shamir's Secret Sharing recovery."""

import pytest

from cryptodb.crypto.recovery import (
    Share,
    recover_secret,
    split_secret,
)
from cryptodb.exceptions import KeyManagementError


class TestSplitSecret:
    def test_split_and_recover(self) -> None:
        secret = b"my-master-key!"
        shares = split_secret(secret, threshold=3, total_shares=5)
        assert len(shares) == 5
        # Recover with exactly threshold shares
        recovered = recover_secret(shares[:3])
        assert recovered == secret

    def test_recover_with_more_than_threshold(self) -> None:
        secret = b"x" * 32
        shares = split_secret(secret, threshold=2, total_shares=5)
        recovered = recover_secret(shares[1:4])
        assert recovered == secret

    def test_recover_with_all_shares(self) -> None:
        secret = b"\x00\x01\x02\xff" * 8
        shares = split_secret(secret, threshold=4, total_shares=4)
        recovered = recover_secret(shares)
        assert recovered == secret

    def test_invalid_threshold_raises(self) -> None:
        with pytest.raises(KeyManagementError):
            split_secret(b"secret", threshold=1, total_shares=3)
        with pytest.raises(KeyManagementError):
            split_secret(b"secret", threshold=3, total_shares=2)
        with pytest.raises(KeyManagementError):
            split_secret(b"secret", threshold=2, total_shares=300)

    def test_empty_shares_raises(self) -> None:
        with pytest.raises(KeyManagementError):
            recover_secret([])

    def test_mismatched_share_lengths_raises(self) -> None:
        secret = b"abc"
        shares = split_secret(secret, threshold=2, total_shares=3)
        bad = Share(index=shares[0].index, value=shares[0].value + b"x")
        with pytest.raises(KeyManagementError):
            recover_secret([shares[0], bad])

    def test_share_serialization(self) -> None:
        secret = b"test-serialization"
        shares = split_secret(secret, threshold=2, total_shares=3)
        b64 = shares[0].to_b64()
        restored = Share.from_b64(b64)
        assert restored.index == shares[0].index
        assert restored.value == shares[0].value
