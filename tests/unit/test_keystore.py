"""Tests for master key store."""

import pytest

from cryptodb.crypto.keystore import MasterKeyStore
from cryptodb.exceptions import KeyManagementError


class TestMasterKeyStore:
    def test_create_and_load(self, temp_dirs):
        ks = MasterKeyStore()
        kek = ks.create_master_key("my-secret-passphrase")
        assert len(kek) == 32
        kek2 = ks.load_master_key("my-secret-passphrase")
        assert kek == kek2

    def test_create_already_exists_raises(self, temp_dirs):
        ks = MasterKeyStore()
        ks.create_master_key("pass1")
        with pytest.raises(KeyManagementError):
            ks.create_master_key("pass2")

    def test_load_not_found_raises(self, temp_dirs):
        ks = MasterKeyStore()
        with pytest.raises(KeyManagementError):
            ks.load_master_key("wrong")

    def test_wrong_passphrase_loads_garbage(self, temp_dirs):
        ks = MasterKeyStore()
        kek = ks.create_master_key("correct")
        kek2 = ks.load_master_key("wrong")
        assert kek != kek2

    def test_list_versions(self, temp_dirs):
        ks = MasterKeyStore()
        ks.create_master_key("p1", "key-a")
        ks.create_master_key("p2", "key-b")
        versions = ks.list_key_versions()
        assert "key-a" in versions
        assert "key-b" in versions

    def test_get_master_key_cached(self, temp_dirs):
        ks = MasterKeyStore()
        kek = ks.create_master_key("pass")
        assert ks.get_master_key() == kek

    def test_get_master_key_not_loaded_raises(self, temp_dirs):
        ks = MasterKeyStore()
        with pytest.raises(KeyManagementError):
            ks.get_master_key()

    def test_rotate_master_key(self, temp_dirs):
        ks = MasterKeyStore()
        kek = ks.create_master_key("old")
        kek2 = ks.rotate_master_key("old", "new")
        assert kek != kek2
        # Should be loadable with new passphrase
        kek3 = ks.load_master_key("new")
        assert kek2 == kek3
        # Old passphrase should fail (loads garbage)
        kek4 = ks.load_master_key("old")
        assert kek4 != kek3

    def test_get_master_key_by_id(self, temp_dirs):
        ks = MasterKeyStore()
        kek_a = ks.create_master_key("p", "key-a")
        kek_b = ks.create_master_key("p", "key-b")
        assert ks.get_master_key_by_id("p", "key-a") == kek_a
        assert ks.get_master_key_by_id("p", "key-b") == kek_b

    def test_custom_keys_dir(self, temp_dirs):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            ks = MasterKeyStore(keys_dir=d)
            ks.create_master_key("p")
            assert (d / "master-key-v1.enc").exists()
