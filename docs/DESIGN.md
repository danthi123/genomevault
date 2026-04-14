# genomevault design notes

This document explains the non-obvious decisions in `genomevault` — why it exists alongside the existing Crypt4GH tooling, what the security trade-offs are, and how the `.gvf` file format relates to the GA4GH standard.

## Why a new tool at all?

The [Crypt4GH](https://github.com/EGA-archive/crypt4gh) specification is the genomics community's endorsed file-encryption standard, shipped by the GA4GH Large-Scale Genomics Work Stream and used in production by the European Genome-phenome Archive (EGA). It is the right underlying technology. What it assumes is a user model that looks like this:

1. User runs `crypt4gh-keygen` to generate an X25519 keypair.
2. User stores the private key somewhere safe.
3. User protects the private key with a passphrase (or doesn't).
4. User uses the keypair with every encrypt/decrypt invocation.

That model works well for bioinformaticians, clinical lab staff, and automated pipelines. It does not work well for an *individual genome owner* — someone who has just walked out of a sequencing appointment with an encrypted drive and wants to be able to decrypt their own data on their own laptop ten years from now, without having had to track a `.sec` file in the interim. For that user, the keypair file is just another thing that can be lost.

`genomevault`'s contribution is exactly one thing: **the passphrase is the key.** A long passphrase, plus the salt stored in the file header, deterministically regenerates the X25519 keypair needed to decrypt.

## The `.gvf` format

```
Offset  Size  Field
------  ----  ---------------------------------
0       11    Magic bytes "GENOMEVAULT"
11      1     Format version (uint8)           — currently 1
12      1     KDF id (uint8)                   — 1 = scrypt
13      1     scrypt N log2 (uint8)            — e.g. 20 => N = 2**20
14      1     scrypt r (uint8)
15      1     scrypt p (uint8)
16      2     Salt length (uint16, big-endian) — currently 32
18      32    Salt
50      ...   Standard Crypt4GH payload (unmodified)
```

Total fixed header overhead: **50 bytes** for a 32-byte salt. Everything after byte 50 is byte-for-byte valid Crypt4GH — you can chop the first 50 bytes off and feed the rest to any Crypt4GH-compatible decoder, provided you also derived and handed it the matching X25519 private key. `genomevault extract` does this split automatically.

## Keypair derivation

```
seed_32 = scrypt(
    passphrase = utf8(passphrase_rstripped_newlines),
    salt       = <32 random bytes from the file header>,
    N          = 2**20,        # cost factor
    r          = 8,
    p          = 1,
    dkLen      = 32,
)

private_key_x25519 = PyNaCl PrivateKey(seed_32)   # applies RFC 7748 clamping
public_key_x25519  = <derived from private_key>
```

The same `(passphrase, salt, N, r, p)` tuple always produces the same keypair. Different salts produce different keypairs. Different passphrases produce different keypairs (one-bit changes in either input cascade through scrypt).

We record `N` as its log2 in a single byte because `N` must be a power of two and values larger than `2**255` are absurd. Reading a header rejects values below a security floor (`N >= 2**14`) so a malicious `.gvf` cannot be crafted with a deliberately cheap KDF.

## Security trade-offs

The design makes three deliberate trade-offs that users should understand. None of them are bugs.

### 1. Passphrase strength IS key strength

With a random X25519 keypair, key strength is ~126 bits regardless of how the keypair is stored. With `genomevault`, key strength is bounded by the passphrase's entropy. A four-word diceware phrase (~51 bits of entropy pre-KDF) combined with scrypt's ~2²⁰ cost factor raises the effective attack cost significantly, but the ceiling is still the passphrase. **Short passphrases are unsafe no matter what.** The CLI refuses passphrases below a length floor and prints visible guidance emphasizing length.

### 2. No revocation

If your passphrase is compromised, the derived keypair is compromised for every `.gvf` file encrypted with it, including files encrypted yesterday. Unlike a random keypair workflow — where you can generate a new keypair and re-encrypt — the only remediation here is to re-encrypt every affected file with a new passphrase. Plan accordingly.

### 3. No recovery

There is no backdoor, no "security question", no vendor-side key escrow. If you forget your passphrase, your data is unreadable. This is a feature: it is the same property we want for the underlying genome itself. If a recovery path existed, then a compelled-disclosure process could also force it. For life-critical genomes, keep a passphrase backup somewhere you trust (password manager, physical safe, split-knowledge paper backup).

## Salt handling

- A fresh 32-byte salt is generated per encryption by default, from `os.urandom`.
- The salt is stored **in the `.gvf` header**, not in a sidecar file. Only the passphrase is separately held by the user.
- Reusing salts across multiple files encrypted with the same passphrase is **not** catastrophic for confidentiality in this model: Crypt4GH's body encryption uses a fresh random session key per file regardless, and the derived X25519 keypair only unwraps that session key. Reuse does weaken the "slow down the attacker" benefit of the KDF if they are brute-forcing multiple files, so we still default to fresh salt per file.

## Why not Argon2id?

scrypt (RFC 7914) is well-studied, implemented in `cryptography.hazmat` and in OS-level primitives, and its memory-hardness profile is appropriate for a user-entered passphrase on a desktop machine. Argon2id is an excellent choice too, and we reserve `kdf_id = 2` in the file header for a future version that switches to it without breaking the format. If you have a strong opinion, please file an issue.

## Interop with other Crypt4GH tools

Run:

```bash
genomevault extract my-genome.vcf.gvf -d ./exported/
```

You get three files:

- `my-genome.vcf.c4gh` — byte-for-byte valid Crypt4GH, openable by `crypt4gh`, `htslib`, or any GA4GH-compatible implementation.
- `my-genome.vcf.seckey.hex` — the derived X25519 private key in lowercase hex, one line. `chmod 0600` applied automatically on POSIX.
- `my-genome.vcf.pubkey.hex` — the public key in the same form.

Every other Crypt4GH implementation expects the secret key in its own format (`crypt4gh` wants a block of base64 in a specific envelope; `htslib-crypt4gh` accepts raw bytes). Converting hex -> your tool's format is a one-liner the user documentation of those tools will explain. We deliberately emit raw hex rather than any specific tool's envelope to avoid locking users into a single downstream path.

## What we don't do

- **We don't compress.** Crypt4GH doesn't compress either. If you care about size, gzip your input before encrypting.
- **We don't obfuscate file types.** A `.gvf` file is immediately recognizable as a genomevault file from its magic bytes. This is intentional — if you need steganographic secrecy, this is the wrong tool.
- **We don't encrypt filenames.** The filename survives unchanged. Use generic names if metadata secrecy matters.
- **We don't sign.** Crypt4GH's `sender_pubkey` parameter can be used for sender authentication, but our passphrase-derived keypair model makes "sender" and "recipient" the same entity by default, so the feature is not exposed.

## Invariants we promise to maintain

- The 11-byte magic and 1-byte version field will stay at offsets 0-11. Any future format revision lives entirely behind that version byte.
- `KDF_SCRYPT = 1` is permanent.
- Salt length up to 65,535 bytes is supported; we use 32 for now.
- A `version=1` file produced by this tool will remain readable by future `genomevault` versions.
