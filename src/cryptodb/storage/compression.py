"""Compression helpers: compress before encrypt."""

import zlib

import zstandard as zstd


class CompressionError(Exception):
    """Base compression error."""


def compress(data: bytes, algorithm: str = "zstd", level: int = 3) -> bytes:
    """Compress *data* and return the payload with a one-byte header."""
    match algorithm:
        case "zstd":
            cctx = zstd.ZstdCompressor(level=level)
            compressed = cctx.compress(data)
            return b"\x01" + compressed
        case "zlib":
            compressed = zlib.compress(data, level=level)
            return b"\x02" + compressed
        case "none":
            return b"\x00" + data
        case _:
            raise CompressionError(f"Unknown compression algorithm: {algorithm}")


def decompress(data: bytes) -> bytes:
    """Decompress data based on the one-byte header."""
    if len(data) < 1:
        raise CompressionError("Data too short")
    header = data[0]
    payload = data[1:]
    match header:
        case 0x00:
            return payload
        case 0x01:
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(payload)
        case 0x02:
            return zlib.decompress(payload)
        case _:
            raise CompressionError(f"Unknown compression header: {header}")
