"""Command-line interface for genomevault.

Subcommands:

* ``encrypt`` — encrypt a file to ``.gvf``
* ``decrypt`` — decrypt a ``.gvf`` file back to plaintext
* ``verify``  — check a ``.gvf`` file's integrity without writing plaintext
* ``info``    — show header metadata (version, salt, KDF params)
* ``extract`` — split a ``.gvf`` into a standard ``.c4gh`` + raw keypair

Design constraint: the CLI must be safe to script in shell pipelines.
When ``--passphrase-stdin`` is passed, the first line of stdin is used as
the passphrase and no prompting happens.  Otherwise, on encrypt we
print guidance and prompt twice; on decrypt/verify/extract we prompt once.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import NoReturn

from genomevault.c4gh_wrap import (
    decrypt_file,
    encrypt_file,
    extract_c4gh,
    peek_header,
    verify_file,
)
from genomevault.passphrase import (
    Strength,
    evaluate,
    prompt_for_existing_passphrase,
    prompt_for_new_passphrase,
)
from genomevault.version import __version__


def _err(msg: str) -> None:
    print(f"genomevault: error: {msg}", file=sys.stderr)


def _fail(msg: str, code: int = 1) -> NoReturn:
    _err(msg)
    raise SystemExit(code)


def _read_passphrase_from_stdin() -> str:
    line = sys.stdin.readline()
    if not line:
        _fail("--passphrase-stdin set but no passphrase was provided on stdin")
    return line.rstrip("\r\n")


def _resolve_new_passphrase(args: argparse.Namespace) -> str:
    """Get a passphrase for encrypt.  Supports stdin fallback, otherwise prompts."""
    if args.passphrase_stdin:
        pw = _read_passphrase_from_stdin()
        report = evaluate(pw)
        if report.strength in (Strength.CATASTROPHIC, Strength.VERY_WEAK):
            _fail(
                f"refusing passphrase supplied on stdin: {report.message}. "
                "Use a longer phrase (20+ characters, 4+ words recommended)."
            )
        if report.strength is Strength.WEAK:
            print(
                f"genomevault: warning: {report.message}", file=sys.stderr
            )
        return pw
    return prompt_for_new_passphrase()


def _resolve_existing_passphrase(args: argparse.Namespace) -> str:
    """Get a passphrase for decrypt/verify/extract."""
    if args.passphrase_stdin:
        return _read_passphrase_from_stdin()
    return prompt_for_existing_passphrase()


def _validate_input(path: Path) -> None:
    if not path.exists():
        _fail(f"input file does not exist: {path}")
    if not path.is_file():
        _fail(f"input path is not a regular file: {path}")


def _default_output(input_path: Path, suffix: str) -> Path:
    """Compute a default output path by appending or stripping suffix."""
    if suffix.startswith("-"):
        # strip style: "-.gvf" means remove trailing .gvf
        strip = suffix[1:]
        name = input_path.name
        if name.endswith(strip):
            return input_path.with_name(name[: -len(strip)])
        return input_path.with_name(name + ".decoded")
    return input_path.with_name(input_path.name + suffix)


def cmd_encrypt(args: argparse.Namespace) -> int:
    input_path = Path(args.input).resolve()
    _validate_input(input_path)
    output_path = Path(args.output).resolve() if args.output else _default_output(
        input_path, ".gvf"
    )

    if output_path.exists() and not args.force:
        _fail(
            f"output file already exists: {output_path} (use --force to overwrite)"
        )

    passphrase = _resolve_new_passphrase(args)
    print(
        f"genomevault: encrypting {input_path.name} "
        f"({input_path.stat().st_size:,} bytes)...",
        file=sys.stderr,
    )
    result = encrypt_file(
        input_path=input_path,
        output_path=output_path,
        passphrase=passphrase,
    )
    print(
        f"genomevault: wrote {output_path} "
        f"({result.output_bytes:,} bytes; "
        f"overhead={result.output_bytes - result.input_bytes:,})",
        file=sys.stderr,
    )
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    input_path = Path(args.input).resolve()
    _validate_input(input_path)
    output_path = Path(args.output).resolve() if args.output else _default_output(
        input_path, "-.gvf"
    )

    if output_path.exists() and not args.force:
        _fail(
            f"output file already exists: {output_path} (use --force to overwrite)"
        )

    passphrase = _resolve_existing_passphrase(args)
    print(f"genomevault: decrypting {input_path.name}...", file=sys.stderr)
    try:
        result = decrypt_file(
            input_path=input_path,
            output_path=output_path,
            passphrase=passphrase,
        )
    except ValueError as e:
        # Clean up partial output on header errors.
        output_path.unlink(missing_ok=True)
        _fail(f"decryption failed: {e}")
    except Exception as e:
        output_path.unlink(missing_ok=True)
        _fail(
            f"decryption failed (likely wrong passphrase or tampered file): {e}"
        )

    print(
        f"genomevault: wrote {output_path} ({result.output_bytes:,} bytes)",
        file=sys.stderr,
    )
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    input_path = Path(args.input).resolve()
    _validate_input(input_path)
    passphrase = _resolve_existing_passphrase(args)
    print(f"genomevault: verifying {input_path.name}...", file=sys.stderr)
    try:
        result = verify_file(input_path, passphrase)
    except Exception as e:
        _fail(f"verification FAILED: {e}")
    print(
        f"genomevault: OK — header version={result.header.version}, "
        f"KDF=scrypt(N={result.header.scrypt_params.n}, "
        f"r={result.header.scrypt_params.r}, "
        f"p={result.header.scrypt_params.p}), "
        f"salt={result.header.salt.hex()}",
        file=sys.stderr,
    )
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    input_path = Path(args.input).resolve()
    _validate_input(input_path)
    try:
        header = peek_header(input_path)
    except ValueError as e:
        _fail(f"not a valid .gvf file: {e}")
    size = input_path.stat().st_size
    print(f"file:           {input_path}")
    print(f"size:           {size:,} bytes")
    print(f"format version: {header.version}")
    print("KDF:            scrypt")
    print(f"  N:            {header.scrypt_params.n} (2^{header.scrypt_params.n.bit_length() - 1})")
    print(f"  r:            {header.scrypt_params.r}")
    print(f"  p:            {header.scrypt_params.p}")
    print(f"salt (hex):     {header.salt.hex()}")
    print(f"salt length:    {len(header.salt)} bytes")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    input_path = Path(args.input).resolve()
    _validate_input(input_path)

    stem = input_path.with_suffix("").name if input_path.suffix == ".gvf" else input_path.name
    out_dir = Path(args.output_dir).resolve() if args.output_dir else input_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    c4gh_out = out_dir / f"{stem}.c4gh"
    sec_out = out_dir / f"{stem}.seckey.hex"
    pub_out = out_dir / f"{stem}.pubkey.hex"

    for p in (c4gh_out, sec_out, pub_out):
        if p.exists() and not args.force:
            _fail(f"output file already exists: {p} (use --force to overwrite)")

    passphrase = _resolve_existing_passphrase(args)
    print(
        f"genomevault: extracting {input_path.name} to Crypt4GH + keypair...",
        file=sys.stderr,
    )
    try:
        header = extract_c4gh(
            input_path=input_path,
            output_c4gh_path=c4gh_out,
            output_seckey_path=sec_out,
            output_pubkey_path=pub_out,
            passphrase=passphrase,
        )
    except Exception as e:
        _fail(f"extraction failed: {e}")

    print(f"genomevault: wrote {c4gh_out}", file=sys.stderr)
    print(f"genomevault: wrote {sec_out} (sensitive — chmod 0600 on POSIX)", file=sys.stderr)
    print(f"genomevault: wrote {pub_out}", file=sys.stderr)
    print(
        f"genomevault: original KDF was scrypt(N={header.scrypt_params.n}, "
        f"r={header.scrypt_params.r}, p={header.scrypt_params.p})",
        file=sys.stderr,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="genomevault",
        description=(
            "Passphrase-based encryption for genomic files. "
            "Wraps the GA4GH Crypt4GH standard with deterministic keypair derivation."
        ),
        epilog=(
            "Passphrase guidance: pick a memorable phrase, not a password. "
            "Length matters more than complexity — a four-word phrase is "
            "stronger than most short complex passwords."
        ),
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    # Shared flags
    def _add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--passphrase-stdin",
            action="store_true",
            help=(
                "read passphrase from the first line of stdin instead of prompting "
                "(useful for scripting; any newlines trailing the phrase are stripped)"
            ),
        )
        p.add_argument(
            "-f",
            "--force",
            action="store_true",
            help="overwrite output files if they already exist",
        )

    p_enc = sub.add_parser(
        "encrypt",
        help="encrypt a file into the .gvf format",
        description="Encrypt a file with a passphrase-derived X25519 keypair.",
    )
    p_enc.add_argument("input", help="path to the plaintext file")
    p_enc.add_argument(
        "-o",
        "--output",
        help="destination .gvf path (default: <input>.gvf)",
    )
    _add_common(p_enc)
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser(
        "decrypt",
        help="decrypt a .gvf file back to plaintext",
        description="Decrypt a .gvf file using the original passphrase.",
    )
    p_dec.add_argument("input", help="path to the .gvf file")
    p_dec.add_argument(
        "-o",
        "--output",
        help="destination plaintext path (default: strip .gvf, else append .decoded)",
    )
    _add_common(p_dec)
    p_dec.set_defaults(func=cmd_decrypt)

    p_vf = sub.add_parser(
        "verify",
        help="check a .gvf file's AEAD tags without writing plaintext",
        description=(
            "Decrypt into /dev/null to confirm every ChaCha20-Poly1305 "
            "segment's authentication tag is intact. Requires passphrase."
        ),
    )
    p_vf.add_argument("input", help="path to the .gvf file")
    _add_common(p_vf)
    p_vf.set_defaults(func=cmd_verify)

    p_info = sub.add_parser(
        "info",
        help="print header metadata for a .gvf file (no decryption)",
        description="Read and print the .gvf header metadata.",
    )
    p_info.add_argument("input", help="path to the .gvf file")
    p_info.set_defaults(func=cmd_info)

    p_ex = sub.add_parser(
        "extract",
        help="split a .gvf into a standard .c4gh file plus raw keypair",
        description=(
            "Extract the Crypt4GH payload unmodified (for interop with other "
            "Crypt4GH tools) alongside the passphrase-derived X25519 keypair "
            "in hex form."
        ),
    )
    p_ex.add_argument("input", help="path to the .gvf file")
    p_ex.add_argument(
        "-d",
        "--output-dir",
        help="directory to write .c4gh + key files (default: same as input)",
    )
    _add_common(p_ex)
    p_ex.set_defaults(func=cmd_extract)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result: int = args.func(args)
    except KeyboardInterrupt:
        print("\ngenomevault: interrupted", file=sys.stderr)
        return 130
    return result


if __name__ == "__main__":
    raise SystemExit(main())
