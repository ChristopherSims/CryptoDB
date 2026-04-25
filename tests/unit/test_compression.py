"""Tests for compression helpers."""

import pytest

from cryptodb.storage.compression import CompressionError, compress, decompress


class TestCompress:
    def test_zstd_roundtrip(self):
        data = b"hello world" * 1000
        compressed = compress(data, algorithm="zstd")
        assert compressed != data
        assert decompress(compressed) == data

    def test_zlib_roundtrip(self):
        data = b"hello world" * 1000
        compressed = compress(data, algorithm="zlib")
        assert compressed != data
        assert decompress(compressed) == data

    def test_none_roundtrip(self):
        data = b"hello world"
        compressed = compress(data, algorithm="none")
        assert compressed[1:] == data
        assert decompress(compressed) == data

    def test_unknown_algorithm_raises(self):
        with pytest.raises(CompressionError):
            compress(b"data", algorithm="unknown")

    def test_different_levels(self):
        data = b"x" * 10000
        c1 = compress(data, algorithm="zstd", level=1)
        c22 = compress(data, algorithm="zstd", level=22)
        # Higher level may produce smaller output (or same)
        assert decompress(c1) == data
        assert decompress(c22) == data


class TestDecompress:
    def test_unknown_header_raises(self):
        with pytest.raises(CompressionError):
            decompress(b"\xffsome data")

    def test_empty_data_raises(self):
        with pytest.raises(CompressionError):
            decompress(b"")

    def test_none_empty_payload(self):
        # header 0x00 with empty payload should return b""
        assert decompress(b"\x00") == b""

    def test_zstd_decompress_only(self):
        data = b"hello world" * 1000
        compressed = compress(data, algorithm="zstd")
        assert decompress(compressed) == data

    def test_zlib_decompress_only(self):
        data = b"hello world" * 1000
        compressed = compress(data, algorithm="zlib")
        assert decompress(compressed) == data
