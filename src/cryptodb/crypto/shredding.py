"""Crypto-shredding: irrecoverable deletion by destroying key material."""

import os

from cryptodb.crypto.envelope import Envelope


class ShreddingError(Exception):
    """Base exception for shredding failures."""


def secure_delete_file(path: str | os.PathLike, passes: int = 3) -> None:
    """Overwrite a file with random data before unlinking.

    Best-effort on modern filesystems (journaling, COW, SSD wear-leveling
    may still retain data). For strong guarantees, use encrypted volumes
    and discard the key.
    """
    file_path = os.fspath(path)
    try:
        size = os.path.getsize(file_path)
        with open(file_path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
    except FileNotFoundError:
        pass
    finally:
        os.remove(file_path)


def shred_envelope(envelope: Envelope) -> None:
    """Mark an envelope as shredded.

    In practice, the DEK is irrecoverable once the EncryptedDataKey record
    is deleted from the metadata store. This function is a no-op placeholder
    to document the intent; the actual shredding happens by deleting the
    metadata row containing *encrypted_dek*.
    """
    # Intentionally a no-op: shredding is achieved by deleting the DEK
    # from the metadata DB. Without the DEK, the ciphertext is worthless.
    pass
