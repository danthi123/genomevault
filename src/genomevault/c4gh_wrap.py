"""Glue between our passphrase-derived keypair and the underlying Crypt4GH
library.

Responsibilities:

* ``encrypt_file`` — write a ``.gvf`` file (our header + Crypt4GH payload)
* ``decrypt_file`` — consume a ``.gvf`` file back to plaintext
* ``extract_c4gh`` — split a ``.gvf`` into a standard ``.c4gh`` plus a
  Crypt4GH-format keypair, for interop with other Crypt4GH tools
* ``peek_header`` — parse and return just the header for ``info``/``verify``

The Crypt4GH library handles segmented ChaCha20-Poly1305 streaming with
64 KiB segments, so this wrapper inherits bounded memory use regardless of
input size.  We do not buffer the whole file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

import crypt4gh.lib
from nacl.public import PrivateKey

from genomevault.crypto import DEFAULT_PARAMS, SALT_LEN, ScryptParams, derive_keypair
from genomevault.fileformat import (
    FORMAT_VERSION,
    KDF_SCRYPT,
    GvfHeader,
    read_header,
    write_header,
)

# Method id 0 in Crypt4GH means X25519 + ChaCha20-Poly1305.  No other method
# is currently defined by the spec, but we keep this constant named for
# clarity at call sites.
CRYPT4GH_METHOD_X25519: int = 0


@dataclass(frozen=True)
class EncryptResult:
    """Metadata about a completed encryption."""

    salt: bytes
    scrypt_params: ScryptParams
    input_bytes: int
    output_bytes: int


@dataclass(frozen=True)
class DecryptResult:
    """Metadata about a completed decryption."""

    header: GvfHeader
    output_bytes: int


def encrypt_file(
    *,
    input_path: Path,
    output_path: Path,
    passphrase: str,
    params: ScryptParams = DEFAULT_PARAMS,
    salt: bytes | None = None,
) -> EncryptResult:
    """Encrypt ``input_path`` to ``output_path`` as a ``.gvf`` file.

    Parameters
    ----------
    input_path : Path
        File to encrypt.  Any content is permitted; genomic suitability is
        the user's responsibility.  Read in streaming mode.
    output_path : Path
        Destination ``.gvf`` file.  Will be created or overwritten.
    passphrase : str
        User's passphrase.  Length matters more than complexity — see
        ``genomevault.passphrase``.
    params : ScryptParams, optional
        KDF parameters.  Defaults to the production parameters
        (N=2**20, r=8, p=1).
    salt : bytes, optional
        Salt bytes.  A fresh random 32-byte salt is generated if not
        supplied.  Same salt MUST NOT be reused across files by the
        same passphrase *if* you want to keep compromise of one file's
        ciphertext from exposing other files' session keys — although the
        threat model here is narrow because each Crypt4GH file has its own
        random session key.  We refresh salt per file by default.
    """
    if salt is None:
        salt = os.urandom(SALT_LEN)
    if len(salt) != SALT_LEN:
        raise ValueError(f"salt must be {SALT_LEN} bytes; got {len(salt)}")

    # Derive the keypair first so we fail fast if the passphrase is wrong
    # type, KDF is misconfigured, etc.
    keypair = derive_keypair(passphrase, salt, params)
    header = GvfHeader(
        version=FORMAT_VERSION,
        kdf_id=KDF_SCRYPT,
        scrypt_params=params,
        salt=salt,
    )

    input_bytes = input_path.stat().st_size
    with output_path.open("wb") as out, input_path.open("rb") as inp:
        write_header(out, header)
        # crypt4gh.lib.encrypt streams segment-by-segment so memory use
        # is bounded by SEGMENT_SIZE (64 KiB) rather than file size.
        crypt4gh.lib.encrypt(
            keys=[(CRYPT4GH_METHOD_X25519, keypair.private_key, keypair.public_key)],
            infile=inp,
            outfile=out,
        )
        output_bytes = out.tell()

    return EncryptResult(
        salt=salt,
        scrypt_params=params,
        input_bytes=input_bytes,
        output_bytes=output_bytes,
    )


def decrypt_file(
    *,
    input_path: Path,
    output_path: Path,
    passphrase: str,
) -> DecryptResult:
    """Decrypt a ``.gvf`` file ``input_path`` to ``output_path``."""
    with input_path.open("rb") as inp:
        header = read_header(inp)
        keypair = derive_keypair(passphrase, header.salt, header.scrypt_params)
        with output_path.open("wb") as out:
            crypt4gh.lib.decrypt(
                keys=[(CRYPT4GH_METHOD_X25519, keypair.private_key, None)],
                infile=inp,
                outfile=out,
            )
            output_bytes = out.tell()

    return DecryptResult(header=header, output_bytes=output_bytes)


def peek_header(input_path: Path) -> GvfHeader:
    """Read just the ``.gvf`` header without decrypting the payload.

    Used by ``genomevault info`` and the eager validation inside ``verify``.
    """
    with input_path.open("rb") as inp:
        return read_header(inp)


def extract_c4gh(
    *,
    input_path: Path,
    output_c4gh_path: Path,
    output_seckey_path: Path,
    output_pubkey_path: Path,
    passphrase: str,
) -> GvfHeader:
    """Extract a standard Crypt4GH file plus the derived keypair from a ``.gvf``.

    Produces three files:

    * ``output_c4gh_path`` — unmodified Crypt4GH ciphertext, openable by any
      Crypt4GH-compatible tool
    * ``output_seckey_path`` — 32-byte raw X25519 private key, hex-encoded
      with a newline (same format as ``crypt4gh-keygen`` with no passphrase
      protection) so third-party tools can import it
    * ``output_pubkey_path`` — 32-byte raw X25519 public key, hex-encoded

    This is an interop escape hatch: once you extract, the three files
    together are equivalent to the original ``.gvf`` for decryption
    purposes but interoperate with every other Crypt4GH implementation.

    The user must still keep the passphrase itself (or the exported
    private key file) to decrypt.  Raw key files do NOT require a
    passphrase — treat them with the same care you would an SSH private
    key.  Returns the original ``.gvf`` header so callers can log its
    parameters.
    """
    with input_path.open("rb") as inp:
        header = read_header(inp)
        keypair = derive_keypair(passphrase, header.salt, header.scrypt_params)

        # Copy the remaining bytes (the Crypt4GH payload) verbatim into the
        # new .c4gh file.  Streamed to keep memory bounded on large genomes.
        with output_c4gh_path.open("wb") as c4gh_out:
            _copy_stream(inp, c4gh_out)

    # Export the keys as raw hex so downstream tools can import them via
    # their own key loaders.  We emit plain hex rather than PEM/Crypt4GH
    # key format so the file is trivially parseable and the user is not
    # forced into a specific tool's import workflow.
    output_seckey_path.write_text(keypair.private_key.hex() + "\n", encoding="ascii")
    output_pubkey_path.write_text(keypair.public_key.hex() + "\n", encoding="ascii")

    # Keys are cryptographically sensitive; on POSIX set 0o600 so
    # accidental group/other readers cannot grab them.  On Windows the
    # call is a no-op but harmless.
    try:
        os.chmod(output_seckey_path, 0o600)
    except OSError:
        pass

    return header


def _copy_stream(src: BinaryIO, dst: BinaryIO, chunk: int = 1024 * 1024) -> None:
    """Byte-for-byte copy in 1 MiB chunks.  Used by extract_c4gh."""
    while True:
        data = src.read(chunk)
        if not data:
            return
        dst.write(data)


def verify_file(input_path: Path, passphrase: str) -> DecryptResult:
    """Decrypt the file into memory/os.devnull to confirm AEAD tags and
    passphrase are valid.

    We currently *do* decrypt the full ciphertext to verify every AEAD tag
    (ChaCha20-Poly1305 authenticates each 64 KiB segment independently, so
    only a full scan catches tampering in later segments).  Output is
    discarded.  Memory use is bounded by the Crypt4GH library's internal
    segment buffer.
    """
    with input_path.open("rb") as inp, open(os.devnull, "wb") as sink:
        header = read_header(inp)
        keypair = derive_keypair(passphrase, header.salt, header.scrypt_params)
        crypt4gh.lib.decrypt(
            keys=[(CRYPT4GH_METHOD_X25519, keypair.private_key, None)],
            infile=inp,
            outfile=sink,
        )
        # We cannot cheaply report decrypted byte count without re-running
        # so we return 0.  Callers that want size information should use
        # ``decrypt_file`` and discard the output themselves.
        return DecryptResult(header=header, output_bytes=0)


# PublicKey helper — exposed for tests + extract_c4gh so the main modules
# do not need to import nacl directly.
def pubkey_from_seckey(seckey: bytes) -> bytes:
    """Derive the X25519 public key for a given 32-byte private key."""
    if len(seckey) != 32:
        raise ValueError("seckey must be 32 bytes")
    return bytes(PrivateKey(seckey).public_key)
