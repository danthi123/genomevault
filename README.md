# genomevault

**Passphrase-based encryption for genomic files.** No key files to manage, no PKI to set up — just a passphrase and your data. Output is the GA4GH-standard [Crypt4GH](https://samtools.github.io/hts-specs/crypt4gh.pdf) file format wrapped with a small header for passphrase-driven decryption.

> [!IMPORTANT]
> **Your passphrase is your only key.** Lose the passphrase, lose the data. There is no recovery path — by design. This is the trade for not having to manage key files.

## Why this exists

The genomics community has a solid encryption standard — [Crypt4GH](https://github.com/EGA-archive/crypt4gh) — but its UX assumes you can manage X25519 keypair files. Most people can't, don't want to, and shouldn't have to. `genomevault` closes that gap: a passphrase alone encrypts and decrypts your `.vcf`, `.fastq`, `.bam`, or `.gvcf` files, and the output remains interoperable with every other Crypt4GH tool.

## Install

```bash
pip install genomevault
```

Requires Python 3.10 or newer.

## Quickstart

```bash
# Encrypt a VCF
genomevault encrypt my-genome.vcf
# → produces my-genome.vcf.gvf

# Decrypt it
genomevault decrypt my-genome.vcf.gvf
# → restores my-genome.vcf

# Check a file without decrypting
genomevault verify my-genome.vcf.gvf
genomevault info my-genome.vcf.gvf

# Extract to standard Crypt4GH + key (for interop with other Crypt4GH tools)
genomevault extract my-genome.vcf.gvf
```

## Passphrase advice

**Length beats complexity.** A four-word phrase like `correct horse battery staple` is stronger than a short complex password like `P@ssw0rd!` — and easier to remember. The tool will warn you if your passphrase is short; follow its guidance.

Good passphrases:
- `the glass wall opens twice each visit`
- `my grandmother kept her recipes in a tin box`
- `sequence once destroy twice keys with me always`

Bad passphrases:
- `password`
- `genome123`
- `Spring2026!`

## How it works (2-minute version)

1. You supply a passphrase.
2. `genomevault` runs `scrypt(passphrase, random-salt, N=2^20, r=8, p=1)` to derive a 32-byte seed.
3. The seed becomes a deterministic X25519 keypair (via libsodium's `crypto_sign_seed_keypair` conversion).
4. Your file is encrypted to the derived public key using standard Crypt4GH (ChaCha20-Poly1305, random session key per file).
5. The salt + scrypt parameters are stored in a small header prepended to the Crypt4GH output — this is the `.gvf` format.
6. To decrypt, the passphrase + salt + same scrypt parameters reproduce the private key, which unlocks the Crypt4GH header.

## File formats

- **`.gvf`** — GenomeVault-native. Contains the salt + KDF parameters + standard Crypt4GH payload. Use this for routine storage.
- **`.c4gh`** — Standard Crypt4GH. Use `genomevault extract` to produce this plus the derived keypair if you need to share the file with someone using a different Crypt4GH tool.

## Security notes

- **Authenticated encryption** — ChaCha20-Poly1305 AEAD (via Crypt4GH). Any tampering with the ciphertext is detected and decryption refuses.
- **Passphrase strength is your ceiling** — the tool uses scrypt with N=2^20 (≈1 second per guess on modern hardware), so brute force requires enormous resources, but a weak passphrase is still weak. Use long phrases.
- **No revocation** — if your passphrase is compromised, you cannot "revoke" the derived keypair. You must re-encrypt all files with a new passphrase. This differs from random keypair workflows (where you can rotate keys).
- **No recovery** — if you forget the passphrase, there is no backdoor. Consider a password manager entry or a physically-secure paper backup for life-critical data.

Full details in [`docs/DESIGN.md`](docs/DESIGN.md). Disclosure policy in [`SECURITY.md`](SECURITY.md).

## Related tools

- [**Crypt4GH**](https://github.com/EGA-archive/crypt4gh) — the underlying standard, for anyone who wants to manage keypair files directly.
- [**crypt4gh-gui**](https://github.com/CSCfi/crypt4gh-gui) — GUI wrapper on top of Crypt4GH, also keyfile-based.
- [**age**](https://github.com/FiloSottile/age) — general-purpose modern file encryption; inspired our UX but is not genomic-data-aware.

## License

MIT — see [`LICENSE`](LICENSE).

## Contributing

Issues and pull requests welcome. Before submitting a PR, please run:

```bash
pip install -e ".[dev]"
pytest
ruff check .
mypy src
```
