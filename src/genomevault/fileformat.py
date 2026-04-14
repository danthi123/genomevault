"""``.gvf`` file format — a thin wrapper around standard Crypt4GH output.

The goal of this wrapper is to carry the salt and KDF parameters alongside
the ciphertext so decryption only requires the user's passphrase.  Because
the ciphertext portion is unmodified Crypt4GH, a ``.gvf`` file can be
converted into a plain ``.c4gh`` file (plus the derived keypair) for
interop with any other Crypt4GH implementation — see
``genomevault.cli.extract``.

Layout (all big-endian, fixed-size)::

    Offset  Size  Field
    ------  ----  ---------------------------------
    0       11    Magic bytes b"GENOMEVAULT"
    11      1     Format version (uint8)           — starts at 1
    12      1     KDF id (uint8)                   — 1 = scrypt
    13      1     scrypt N log2 (uint8)            — e.g. 20 means N = 2**20
    14      1     scrypt r (uint8)
    15      1     scrypt p (uint8)
    16      2     Salt length (uint16, big-endian) — currently fixed at 32
    18      N     Salt (N bytes, currently 32)
    50      ...   Crypt4GH payload (variable)

Total fixed header = 50 bytes with a 32-byte salt.  Salt length is a
variable-width field so future versions can use stronger salts without
breaking parsing.

Forward compatibility
---------------------
Readers should refuse any version they do not understand.  When we bump
``FORMAT_VERSION`` we promise the magic + version fields remain at the
same offsets so old readers can still produce a helpful error.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from io import BufferedReader
from typing import BinaryIO, Final

from genomevault.crypto import SALT_LEN, ScryptParams

MAGIC: Final[bytes] = b"GENOMEVAULT"
MAGIC_LEN: Final[int] = len(MAGIC)  # 11
FORMAT_VERSION: Final[int] = 1

# KDF identifiers.  Only scrypt is supported today; the field exists so
# alternative KDFs (Argon2id, PBKDF2) could be added without breaking the
# layout.
KDF_SCRYPT: Final[int] = 1

# Fixed portion of the header = magic + version + kdf + Nlog2 + r + p +
# salt_length.  The salt itself is variable but we always write 32 bytes.
FIXED_HEADER_LEN: Final[int] = MAGIC_LEN + 1 + 1 + 1 + 1 + 1 + 2  # 18 bytes
HEADER_LEN: Final[int] = FIXED_HEADER_LEN + SALT_LEN  # 50 bytes with 32-byte salt


@dataclass(frozen=True)
class GvfHeader:
    """Parsed representation of a ``.gvf`` file header."""

    version: int
    kdf_id: int
    scrypt_params: ScryptParams
    salt: bytes

    def to_bytes(self) -> bytes:
        """Serialize this header to its on-disk byte form."""
        if len(self.salt) > 0xFFFF:
            raise ValueError("salt longer than 65535 bytes is not supported")
        n_log2 = self.scrypt_params.n.bit_length() - 1
        if 2**n_log2 != self.scrypt_params.n:
            raise ValueError("scrypt N must be a power of two")
        if not (0 < n_log2 < 256):
            raise ValueError(f"scrypt N out of range for 1 byte log2: {self.scrypt_params.n}")
        if not (0 < self.scrypt_params.r < 256):
            raise ValueError(f"scrypt r out of 1-byte range: {self.scrypt_params.r}")
        if not (0 < self.scrypt_params.p < 256):
            raise ValueError(f"scrypt p out of 1-byte range: {self.scrypt_params.p}")

        return (
            MAGIC
            + struct.pack(
                ">BBBBBH",
                self.version,
                self.kdf_id,
                n_log2,
                self.scrypt_params.r,
                self.scrypt_params.p,
                len(self.salt),
            )
            + self.salt
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> GvfHeader:
        """Parse a fixed-portion header plus its salt out of raw bytes.

        Convenience wrapper for in-memory tests; production code should use
        ``read_header`` so that partial reads of a large encrypted file do
        not require loading the whole ciphertext.
        """
        if len(data) < FIXED_HEADER_LEN:
            raise ValueError(
                f"data too short for gvf header: got {len(data)} bytes, "
                f"need at least {FIXED_HEADER_LEN}"
            )
        magic = data[:MAGIC_LEN]
        if magic != MAGIC:
            raise ValueError(f"not a .gvf file: bad magic {magic!r}")
        version, kdf_id, n_log2, r, p, salt_len = struct.unpack(
            ">BBBBBH", data[MAGIC_LEN : MAGIC_LEN + 7]
        )
        if version != FORMAT_VERSION:
            raise ValueError(
                f"unsupported .gvf format version {version}; "
                f"this genomevault supports version {FORMAT_VERSION}"
            )
        if kdf_id != KDF_SCRYPT:
            raise ValueError(f"unsupported KDF id {kdf_id}; only scrypt ({KDF_SCRYPT}) is known")
        total_expected = FIXED_HEADER_LEN + salt_len
        if len(data) < total_expected:
            raise ValueError(
                f"data too short for salt: need {total_expected} bytes, have {len(data)}"
            )
        salt = data[FIXED_HEADER_LEN:total_expected]
        params = ScryptParams(n=2**n_log2, r=r, p=p)
        params.validate()
        return cls(version=version, kdf_id=kdf_id, scrypt_params=params, salt=salt)


def write_header(stream: BinaryIO, header: GvfHeader) -> None:
    """Write ``header`` to ``stream`` at its current position."""
    stream.write(header.to_bytes())


def read_header(stream: BufferedReader | BinaryIO) -> GvfHeader:
    """Read and parse a ``.gvf`` header from the current position of ``stream``.

    On return, the stream is positioned at the first byte of the Crypt4GH
    payload.  Raises ``ValueError`` if the header is malformed or uses an
    unsupported version / KDF / security floor.
    """
    fixed = stream.read(FIXED_HEADER_LEN)
    if len(fixed) < FIXED_HEADER_LEN:
        raise ValueError(
            f"truncated .gvf: header needs {FIXED_HEADER_LEN} bytes, got {len(fixed)}"
        )
    magic = fixed[:MAGIC_LEN]
    if magic != MAGIC:
        raise ValueError(f"not a .gvf file: bad magic {magic!r}")
    version, kdf_id, n_log2, r, p, salt_len = struct.unpack(
        ">BBBBBH", fixed[MAGIC_LEN : MAGIC_LEN + 7]
    )
    if version != FORMAT_VERSION:
        raise ValueError(
            f"unsupported .gvf format version {version}; "
            f"this genomevault supports version {FORMAT_VERSION}"
        )
    if kdf_id != KDF_SCRYPT:
        raise ValueError(f"unsupported KDF id {kdf_id}; only scrypt ({KDF_SCRYPT}) is known")
    salt = stream.read(salt_len)
    if len(salt) != salt_len:
        raise ValueError(f"truncated .gvf salt: expected {salt_len} bytes, got {len(salt)}")
    params = ScryptParams(n=2**n_log2, r=r, p=p)
    params.validate()
    return GvfHeader(version=version, kdf_id=kdf_id, scrypt_params=params, salt=salt)
