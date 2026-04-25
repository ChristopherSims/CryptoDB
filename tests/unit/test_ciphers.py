"""Tests for low-level symmetric ciphers."""

import pytest

from cryptodb.crypto.ciphers import AES256GCM, XChaCha20Poly1305Cipher, cipher_factory, _XCHACHA_AVAILABLE


class TestAES256GCM:
    def test_roundtrip(self):
        key = AES256GCM.generate_key()
        aes = AES256GCM.from_key(key)
        plaintext = b"hello world"
        ciphertext = aes.encrypt(plaintext)
        assert ciphertext != plaintext
        decrypted = aes.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_different_nonces_each_time(self):
        key = AES256GCM.generate_key()
        aes = AES256GCM.from_key(key)
        ct1 = aes.encrypt(b"hello")
        ct2 = aes.encrypt(b"hello")
        assert ct1 != ct2

    def test_wrong_key_fails(self):
        key1 = AES256GCM.generate_key()
        key2 = AES256GCM.generate_key()
        aes = AES256GCM.from_key(key1)
        ciphertext = aes.encrypt(b"secret")
        aes2 = AES256GCM.from_key(key2)
        with pytest.raises(Exception):
            aes2.decrypt(ciphertext)

    def test_key_size_validation(self):
        with pytest.raises(ValueError):
            AES256GCM(b"short")

    def test_short_ciphertext_fails(self):
        key = AES256GCM.generate_key()
        aes = AES256GCM.from_key(key)
        with pytest.raises(ValueError):
            aes.decrypt(b"\x00")

    def test_associated_data(self):
        key = AES256GCM.generate_key()
        aes = AES256GCM.from_key(key)
        ct = aes.encrypt(b"msg", associated_data=b"aad")
        assert aes.decrypt(ct, associated_data=b"aad") == b"msg"
        with pytest.raises(Exception):
            aes.decrypt(ct, associated_data=b"wrong")

    def test_generate_key_length(self):
        key = AES256GCM.generate_key()
        assert len(key) == 32


class TestXChaCha20Poly1305:
    @pytest.mark.skipif(not _XCHACHA_AVAILABLE, reason="XChaCha20Poly1305 not available")
    def test_roundtrip(self):
        key = XChaCha20Poly1305Cipher.generate_key()
        cipher = XChaCha20Poly1305Cipher.from_key(key)
        plaintext = b"hello world"
        ciphertext = cipher.encrypt(plaintext)
        assert ciphertext != plaintext
        assert cipher.decrypt(ciphertext) == plaintext

    @pytest.mark.skipif(not _XCHACHA_AVAILABLE, reason="XChaCha20Poly1305 not available")
    def test_key_size_validation(self):
        with pytest.raises(ValueError):
            XChaCha20Poly1305Cipher(b"short")

    @pytest.mark.skipif(not _XCHACHA_AVAILABLE, reason="XChaCha20Poly1305 not available")
    def test_generate_key_length(self):
        key = XChaCha20Poly1305Cipher.generate_key()
        assert len(key) == 32


class TestCipherFactory:
    def test_aes_256_gcm(self):
        key = AES256GCM.generate_key()
        cipher = cipher_factory("aes-256-gcm", key)
        assert isinstance(cipher, AES256GCM)

    @pytest.mark.skipif(not _XCHACHA_AVAILABLE, reason="XChaCha20Poly1305 not available")
    def test_xchacha20_poly1305(self):
        key = XChaCha20Poly1305Cipher.generate_key()
        cipher = cipher_factory("xchacha20-poly1305", key)
        assert isinstance(cipher, XChaCha20Poly1305Cipher)

    def test_unknown_cipher_raises(self):
        with pytest.raises(ValueError):
            cipher_factory("unknown", b"x" * 32)
