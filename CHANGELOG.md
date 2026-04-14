# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-04-14

First public release.

### Added

- Passphrase-based encryption of arbitrary files via `genomevault encrypt`, producing the `.gvf` format: a 50-byte header (magic, version, KDF id, scrypt parameters, salt) followed by an unmodified Crypt4GH payload.
- Decryption via `genomevault decrypt`, which reproduces the original plaintext from a `.gvf` file using only the passphrase.
- Integrity verification via `genomevault verify`, which scans the entire ciphertext, checking every ChaCha20-Poly1305 segment tag, without writing plaintext to disk.
- Header inspection via `genomevault info`, which prints format version, KDF parameters, and salt without decrypting.
- Interop export via `genomevault extract`, producing a standard `.c4gh` file plus the derived keypair in hex for use with any Crypt4GH-compatible tool.
- `--passphrase-stdin` flag on all subcommands for scripting.
- Length-focused passphrase strength evaluation: rejects catastrophic (blocklist) and very weak passphrases, warns on weak, and accepts anything 20+ characters. No complexity rules.
- `ScryptParams` with a security floor (`N >= 2**14`) that is enforced on both encode and decode so files cannot be crafted with a deliberately cheap KDF.
- Full test suite covering crypto determinism, file-format round trips, tampering detection (single-bit and truncation), large-file streaming, CLI behavior, and interop extraction.

### Supported Python versions

- 3.10, 3.11, 3.12

### Dependencies

- `cryptography >= 42.0` (scrypt)
- `crypt4gh >= 1.7` (Crypt4GH file format)
- `pynacl >= 1.5` (X25519 keypair construction)

[0.1.0]: https://github.com/danthi123/genomevault/releases/tag/v0.1.0
