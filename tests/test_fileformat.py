"""Tests for genomevault.fileformat — .gvf header serialization."""

from __future__ import annotations

import io
import os

import pytest

from genomevault.crypto import SALT_LEN, ScryptParams
from genomevault.fileformat import (
    FIXED_HEADER_LEN,
    FORMAT_VERSION,
    HEADER_LEN,
    KDF_SCRYPT,
    MAGIC,
    GvfHeader,
    read_header,
    write_header,
)


def make_header(salt: bytes | None = None, params: ScryptParams | None = None) -> GvfHeader:
    return GvfHeader(
        version=FORMAT_VERSION,
        kdf_id=KDF_SCRYPT,
        scrypt_params=params or ScryptParams(n=2**20, r=8, p=1),
        salt=salt or os.urandom(SALT_LEN),
    )


class TestRoundTrip:
    def test_bytes_roundtrip(self) -> None:
        h1 = make_header()
        serialized = h1.to_bytes()
        assert len(serialized) == HEADER_LEN
        h2 = GvfHeader.from_bytes(serialized)
        assert h1 == h2

    def test_stream_roundtrip(self) -> None:
        h1 = make_header()
        buf = io.BytesIO()
        write_header(buf, h1)
        buf.seek(0)
        h2 = read_header(buf)
        assert h1 == h2
        # Stream should be positioned right after the header
        assert buf.tell() == HEADER_LEN

    def test_payload_follows_header_cleanly(self) -> None:
        h1 = make_header()
        buf = io.BytesIO()
        write_header(buf, h1)
        payload = b"MOCK_CRYPT4GH_PAYLOAD" * 100
        buf.write(payload)
        buf.seek(0)
        h2 = read_header(buf)
        assert h1 == h2
        rest = buf.read()
        assert rest == payload


class TestHeaderSizes:
    def test_fixed_header_length_matches_spec(self) -> None:
        # 11 (magic) + 1 (version) + 1 (kdf) + 1 (Nlog2) + 1 (r) + 1 (p) + 2 (saltlen)
        assert FIXED_HEADER_LEN == 18

    def test_total_header_with_32byte_salt(self) -> None:
        assert HEADER_LEN == 50

    def test_magic_is_11_bytes_ascii(self) -> None:
        assert MAGIC == b"GENOMEVAULT"
        assert len(MAGIC) == 11
        assert MAGIC.isascii()


class TestBadHeaders:
    def test_short_data_rejected(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            GvfHeader.from_bytes(b"GENO")

    def test_bad_magic_rejected(self) -> None:
        bad = b"NOT_GVF_123" + b"\x00" * (HEADER_LEN - 11)
        with pytest.raises(ValueError, match="bad magic"):
            GvfHeader.from_bytes(bad)

    def test_unsupported_version_rejected(self) -> None:
        h = make_header()
        blob = bytearray(h.to_bytes())
        blob[11] = 99  # version byte
        with pytest.raises(ValueError, match="unsupported .gvf format version"):
            GvfHeader.from_bytes(bytes(blob))

    def test_unsupported_kdf_rejected(self) -> None:
        h = make_header()
        blob = bytearray(h.to_bytes())
        blob[12] = 99  # kdf id byte
        with pytest.raises(ValueError, match="unsupported KDF id"):
            GvfHeader.from_bytes(bytes(blob))

    def test_weak_scrypt_params_rejected(self) -> None:
        # Construct a header manually with N=2**10 which is below our floor.
        blob = bytearray()
        blob += MAGIC
        blob += bytes([FORMAT_VERSION, KDF_SCRYPT, 10, 8, 1])
        blob += (32).to_bytes(2, "big")
        blob += os.urandom(32)
        with pytest.raises(ValueError, match="below minimum"):
            GvfHeader.from_bytes(bytes(blob))

    def test_truncated_salt_rejected(self) -> None:
        h = make_header()
        blob = h.to_bytes()[:-5]  # chop salt bytes off the end
        with pytest.raises(ValueError, match="too short for salt"):
            GvfHeader.from_bytes(blob)

    def test_stream_truncated_before_salt(self) -> None:
        buf = io.BytesIO(b"GENOMEVAULT\x01\x01\x14\x08\x01\x00\x20")  # advertises 32 salt bytes
        # Stream has fixed header but no salt.
        with pytest.raises(ValueError, match="truncated .gvf salt"):
            read_header(buf)

    def test_stream_truncated_in_fixed_header(self) -> None:
        buf = io.BytesIO(b"GENO")
        with pytest.raises(ValueError, match="truncated .gvf"):
            read_header(buf)


class TestToBytesValidation:
    def test_non_power_of_two_N_rejected_on_serialize(self) -> None:
        bad_params = ScryptParams.__new__(ScryptParams)
        object.__setattr__(bad_params, "n", 3)
        object.__setattr__(bad_params, "r", 8)
        object.__setattr__(bad_params, "p", 1)
        h = GvfHeader(
            version=FORMAT_VERSION, kdf_id=KDF_SCRYPT, scrypt_params=bad_params, salt=b"\x00" * 32
        )
        with pytest.raises(ValueError, match="power of two"):
            h.to_bytes()

    def test_salt_over_64KiB_rejected(self) -> None:
        h = GvfHeader(
            version=FORMAT_VERSION,
            kdf_id=KDF_SCRYPT,
            scrypt_params=ScryptParams(n=2**20, r=8, p=1),
            salt=b"\x00" * (0x10000),  # 65536 bytes
        )
        with pytest.raises(ValueError, match="65535"):
            h.to_bytes()
