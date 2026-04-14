"""Deterministic X25519 keypair derivation from a passphrase.

Uses scrypt as the KDF (RFC 7914) to turn a passphrase + salt into a 32-byte
seed, then interprets that seed as an X25519 private scalar.  The resulting
keypair is what Crypt4GH uses for header encryption.

Security notes
--------------
* scrypt is memory-hard; parameters below (N=2**20, r=8, p=1) take roughly
  1 second and 1 GiB of RAM per guess on a modern laptop.  This is
  deliberately expensive to make brute-force attacks impractical unless the
  passphrase is very short or a known pattern.
* The caller MUST store the salt and KDF parameters alongside the
  ciphertext so the same key can be regenerated at decrypt time.  The
  ``.gvf`` file format handled in ``genomevault.fileformat`` does exactly
  this.
* The 32-byte output is used directly as the X25519 private scalar.  Per
  RFC 7748 the library performs the standard clamping before any scalar
  multiplication, so any 32-byte input is a valid private key.
* Passphrase strength IS key strength.  A weak passphrase produces a
  weak key regardless of the KDF.  See ``genomevault.passphrase`` for
  user-facing guidance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from nacl.public import PrivateKey, PublicKey

# Default KDF parameters.  N must be a power of two and >= 2**10; increasing N
# doubles both memory and CPU cost.  r and p are usually kept at the reference
# values.  DK_LEN is fixed at 32 bytes because that is the size of an X25519
# private scalar.
DEFAULT_SCRYPT_N: Final[int] = 2**20  # 2^20 = 1,048,576 iterations
DEFAULT_SCRYPT_R: Final[int] = 8
DEFAULT_SCRYPT_P: Final[int] = 1
DK_LEN: Final[int] = 32
SALT_LEN: Final[int] = 32

# Minimum values we will actually accept when reading a file header.  These
# protect against somebody crafting a ``.gvf`` with a deliberately weak KDF
# setting (so that a brute-force attacker only needs a fraction of a second
# per guess).  The absolute floor is below the default by design so files
# created on weaker machines remain readable, but anything below this is
# refused.
MIN_SCRYPT_N: Final[int] = 2**14  # ~16k iterations — slow enough to slow brute force
MIN_SCRYPT_R: Final[int] = 8
MIN_SCRYPT_P: Final[int] = 1


@dataclass(frozen=True)
class ScryptParams:
    """KDF parameters recorded in the file header."""

    n: int  # cost factor, power of two
    r: int  # block size factor
    p: int  # parallelization factor

    def validate(self) -> None:
        """Reject malformed or insecure-by-structure parameter choices."""
        if self.n < 2 or (self.n & (self.n - 1)) != 0:
            raise ValueError(f"scrypt N must be a power of two >= 2; got {self.n}")
        if self.r < 1 or self.p < 1:
            raise ValueError(f"scrypt r and p must be >= 1; got r={self.r} p={self.p}")
        if self.n < MIN_SCRYPT_N or self.r < MIN_SCRYPT_R or self.p < MIN_SCRYPT_P:
            raise ValueError(
                "scrypt parameters below minimum security floor: "
                f"N={self.n} r={self.r} p={self.p} (floor N={MIN_SCRYPT_N})"
            )


DEFAULT_PARAMS: Final[ScryptParams] = ScryptParams(
    n=DEFAULT_SCRYPT_N, r=DEFAULT_SCRYPT_R, p=DEFAULT_SCRYPT_P
)


@dataclass(frozen=True)
class DerivedKeyPair:
    """Result of deriving a keypair from a passphrase.

    Holds both the 32-byte raw X25519 private and public key bytes.  Callers
    that want nacl or cryptography-library objects can reconstruct them from
    these bytes; the goal of this type is to be the single canonical output
    of the KDF step so tests and the rest of the codebase speak one language.
    """

    private_key: bytes  # 32 bytes, X25519 private scalar
    public_key: bytes  # 32 bytes, X25519 public key (u-coordinate)

    def __post_init__(self) -> None:
        if len(self.private_key) != DK_LEN:
            raise ValueError(f"private_key must be {DK_LEN} bytes")
        if len(self.public_key) != DK_LEN:
            raise ValueError(f"public_key must be {DK_LEN} bytes")


def derive_seed(passphrase: str, salt: bytes, params: ScryptParams = DEFAULT_PARAMS) -> bytes:
    """Return a 32-byte seed derived from ``passphrase`` and ``salt``.

    Normalization: the passphrase is encoded as UTF-8 after stripping
    trailing newlines only.  We deliberately do *not* perform Unicode
    normalization (NFKD/NFC) so that input from copy/paste and typed
    input round-trip consistently.  Callers that want canonicalization
    should normalize before calling.
    """
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be a str")
    if not passphrase:
        raise ValueError("passphrase must be non-empty")
    if len(salt) != SALT_LEN:
        raise ValueError(f"salt must be {SALT_LEN} bytes; got {len(salt)}")
    params.validate()

    kdf = Scrypt(
        salt=salt,
        length=DK_LEN,
        n=params.n,
        r=params.r,
        p=params.p,
    )
    result: bytes = kdf.derive(passphrase.rstrip("\r\n").encode("utf-8"))
    return result


def derive_keypair(
    passphrase: str, salt: bytes, params: ScryptParams = DEFAULT_PARAMS
) -> DerivedKeyPair:
    """Derive an X25519 keypair from ``passphrase`` and ``salt``.

    Deterministic: given the same passphrase, salt, and parameters, the
    returned private/public keys are bit-identical.  This is the whole
    point — the user's passphrase is the only thing they need to remember.
    """
    seed = derive_seed(passphrase, salt, params)
    # PyNaCl's PrivateKey constructor accepts a 32-byte private scalar and
    # performs the X25519 clamping internally per RFC 7748.  The resulting
    # public key is the scalar multiplication with the curve base point.
    priv = PrivateKey(seed)
    pub: PublicKey = priv.public_key
    return DerivedKeyPair(
        private_key=bytes(priv),
        public_key=bytes(pub),
    )
