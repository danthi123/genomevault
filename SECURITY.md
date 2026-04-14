# Security Policy

## Reporting a vulnerability

Please email **github@dant123.com** with the subject line `genomevault security`.

Do not disclose the issue publicly until there has been a reasonable opportunity to address it.

When reporting, please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce
- Any suggested remediation
- Proof-of-concept code or test vectors if available

## What to expect

| Timeline    | What happens                                                      |
|-------------|-------------------------------------------------------------------|
| 72 hours    | Acknowledgement of the report                                     |
| 7 days      | Initial assessment and confirmation of whether the issue is valid |
| 30 days     | Fix deployed for confirmed vulnerabilities                        |
| 90 days     | Public disclosure window (per coordinated-disclosure convention)  |

## Scope

**In scope:**

- The `genomevault` Python package and its CLI
- `.gvf` format parsing and the KDF parameter handling
- Key derivation, scrypt parameters, X25519 key handling

**Out of scope:**

- Vulnerabilities in upstream dependencies (`crypt4gh`, `cryptography`, `pynacl`) — report those to the respective projects
- Cryptanalysis of published, peer-reviewed primitives (X25519, ChaCha20-Poly1305, scrypt) — those reports belong in the academic literature
- Weak passphrase choices made by end users — the tool warns about this loudly but cannot prevent it

## Safe harbor

Security research conducted in good faith, including the investigation of vulnerabilities by means that do not disrupt other users or data, is welcome. We will not pursue legal action against researchers who:

- Act in good faith to avoid privacy violations, data destruction, and service disruption
- Only interact with accounts or data they own
- Report vulnerabilities promptly and do not exploit them beyond what is necessary to demonstrate the issue
- Allow a reasonable disclosure window before publishing

## Known limitations

These are **not** bugs, but users should understand them:

1. **Passphrase strength caps key strength.** A weak passphrase produces a weak key regardless of the scrypt cost factor. Use a long passphrase; see the CLI guidance.
2. **No recovery path.** Forgotten passphrases cannot be recovered by any party including the original author. This is by design.
3. **Deterministic keypairs have no revocation.** If a passphrase is exposed, every file encrypted with it is exposed. Rotate the passphrase and re-encrypt affected files.
4. **Not a secure-deletion tool.** `genomevault` encrypts files; securely erasing the plaintext after encryption is the user's responsibility.
5. **No protection against malware on the decryption host.** If the device running `genomevault decrypt` is compromised, the plaintext is exposed.
