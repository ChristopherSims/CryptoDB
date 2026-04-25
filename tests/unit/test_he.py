"""Unit tests for homomorphic encryption."""

import pytest

from cryptodb.crypto.he import HEEncryptedNumber, PaillierHE


class TestPaillierHE:
    def test_encrypt_decrypt_int(self) -> None:
        pub, priv = PaillierHE.generate_keypair()
        he = PaillierHE.from_keypair(pub, priv)
        enc = he.encrypt(42)
        assert he.decrypt(enc) == 42

    def test_encrypt_decrypt_float(self) -> None:
        pub, priv = PaillierHE.generate_keypair()
        he = PaillierHE.from_keypair(pub, priv)
        enc = he.encrypt(3.14)
        decrypted = he.decrypt(enc)
        assert abs(decrypted - 3.14) < 0.01

    def test_homomorphic_addition(self) -> None:
        pub, priv = PaillierHE.generate_keypair()
        he = PaillierHE.from_keypair(pub, priv)
        a = he.encrypt(10)
        b = he.encrypt(20)
        result = he.add(a, b)
        assert he.decrypt(result) == 30

    def test_homomorphic_scalar_multiply(self) -> None:
        pub, priv = PaillierHE.generate_keypair()
        he = PaillierHE.from_keypair(pub, priv)
        a = he.encrypt(5)
        result = he.multiply_scalar(a, 4)
        assert he.decrypt(result) == 20

    def test_serialization_roundtrip(self) -> None:
        pub, priv = PaillierHE.generate_keypair()
        he = PaillierHE.from_keypair(pub, priv)
        enc = he.encrypt(99)
        d = enc.to_dict()
        restored = HEEncryptedNumber.from_dict(d)
        assert he.decrypt(restored) == 99

    def test_private_key_serialization(self) -> None:
        pub, priv = PaillierHE.generate_keypair()
        he = PaillierHE.from_keypair(pub, priv)
        data = PaillierHE.serialize_private_key(priv)
        restored_priv = PaillierHE.deserialize_private_key(pub, data)
        he2 = PaillierHE.from_keypair(pub, restored_priv)
        enc = he2.encrypt(123)
        assert he2.decrypt(enc) == 123
