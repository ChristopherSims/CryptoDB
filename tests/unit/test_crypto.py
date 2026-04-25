"""Unit tests for cryptographic primitives."""

import pytest

from cryptodb.crypto.ciphers import AES256GCM, XChaCha20Poly1305Cipher, _XCHACHA_AVAILABLE
from cryptodb.crypto.envelope import EnvelopeCipher
from cryptodb.crypto.integrity import compute_hmac, verify_hmac
from cryptodb.crypto.searchable import SearchableCipher


class TestCiphers:
    def test_aes_gcm_roundtrip(self) -> None:
        key = AES256GCM.generate_key()
        cipher = AES256GCM.from_key(key)
        plaintext = b"hello world"
        ct = cipher.encrypt(plaintext)
        assert cipher.decrypt(ct) == plaintext

    @pytest.mark.skipif(not _XCHACHA_AVAILABLE, reason="XChaCha20Poly1305 not available")
    def test_xchacha20_roundtrip(self) -> None:
        key = XChaCha20Poly1305Cipher.generate_key()
        cipher = XChaCha20Poly1305Cipher.from_key(key)
        plaintext = b"hello world"
        ct = cipher.encrypt(plaintext)
        assert cipher.decrypt(ct) == plaintext


class TestEnvelope:
    def test_envelope_roundtrip(self) -> None:
        master_key = AES256GCM.generate_key()
        env = EnvelopeCipher(master_key)
        plaintext = b"secret data"
        envelope = env.encrypt(plaintext)
        decrypted = env.decrypt(envelope)
        assert decrypted == plaintext


class TestIntegrity:
    def test_hmac_verification(self) -> None:
        key = b"super-secret-key-for-hmac-test!!"
        data = b"important payload"
        token = compute_hmac(data, key)
        assert verify_hmac(data, token, key) is True
        assert verify_hmac(b"tampered", token, key) is False


class TestSearchable:
    def test_deterministic_index(self) -> None:
        key = b"x" * 32
        sc = SearchableCipher(key)
        idx1 = sc.index("hello", field_name="email")
        idx2 = sc.index("hello", field_name="email")
        assert idx1.token == idx2.token

    def test_encrypt_decrypt(self) -> None:
        key = b"x" * 32
        sc = SearchableCipher(key)
        plaintext = b"find me"
        ct = sc.encrypt_deterministic(plaintext, field_name="tag")
        assert sc.decrypt_deterministic(ct, field_name="tag") == plaintext
