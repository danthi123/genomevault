"""genomevault — passphrase-based encryption for genomic files.

Wraps the GA4GH Crypt4GH standard with deterministic keypair derivation
so end users never have to manage X25519 keypair files.
"""

from genomevault.version import __version__

__all__ = ["__version__"]
