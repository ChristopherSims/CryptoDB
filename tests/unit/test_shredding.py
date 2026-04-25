"""Tests for crypto-shredding module."""

import os
import tempfile

from cryptodb.crypto.shredding import secure_delete_file, shred_envelope
from cryptodb.crypto.envelope import Envelope, EncryptedDataKey


class TestSecureDeleteFile:
    def test_deletes_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"secret data")
            path = f.name
        assert os.path.exists(path)
        secure_delete_file(path)
        assert not os.path.exists(path)

    def test_overwrites_content(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"A" * 1024)
            path = f.name
        secure_delete_file(path, passes=1)
        assert not os.path.exists(path)

    def test_missing_file_no_error(self):
        # Should not raise FileNotFoundError
        secure_delete_file("/nonexistent/path/file.txt")
        assert True

    def test_custom_passes(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"B" * 512)
            path = f.name
        secure_delete_file(path, passes=5)
        assert not os.path.exists(path)


class TestShredEnvelope:
    def test_is_noop(self):
        edek = EncryptedDataKey(ciphertext=b"x", iv=b"n" * 12, algorithm="aes-256-gcm-wrap")
        env = Envelope(encrypted_dek=edek, ciphertext=b"c", cipher_name="aes", record_id="r1")
        # Should not raise
        shred_envelope(env)
