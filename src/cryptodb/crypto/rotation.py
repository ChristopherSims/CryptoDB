"""Key rotation logic: re-encrypt DEKs under a new master key."""

from cryptodb.crypto.envelope import Envelope, EnvelopeCipher


class RotationError(Exception):
    """Base exception for rotation failures."""


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
