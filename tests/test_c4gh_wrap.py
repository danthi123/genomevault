"""End-to-end encryption/decryption tests via the Crypt4GH wrapper."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from genomevault.c4gh_wrap import (
    decrypt_file,
    encrypt_file,
    extract_c4gh,
    peek_header,
    pubkey_from_seckey,
    verify_file,
)
from genomevault.crypto import ScryptParams

# Use a weakened test param set so per-test KDF runs take milliseconds, not
# seconds.  The on-disk format supports any valid ScryptParams so this has
# no bearing on the format's production behavior — we test the security
# floor separately in test_crypto.py / test_fileformat.py.
TEST_PARAMS = ScryptParams(n=2**14, r=8, p=1)
TEST_PASSPHRASE = "the glass wall opens twice each visit"


@pytest.fixture
def tmp_plaintext(tmp_path: Path) -> Path:
    p = tmp_path / "sample.vcf"
    # Small but realistic-ish VCF snippet.  Non-trivially sized so that
    # we exercise at least one full Crypt4GH segment (64 KiB) for some
    # tests.
    content = (
        "##fileformat=VCFv4.2\n"
        "##INFO=<ID=DP,Number=1,Type=Integer,Description=\"Read depth\">\n"
        "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n"
    ) + "\n".join(
        f"chr1\t{i}\trs{i}\tA\tG\t60\tPASS\tDP=30"
        for i in range(1, 2001)
    ) + "\n"
    p.write_text(content, encoding="ascii")
    return p


@pytest.fixture
def tmp_large_plaintext(tmp_path: Path) -> Path:
    """~5 MiB file — crosses multiple Crypt4GH segment boundaries."""
    p = tmp_path / "sample.fastq"
    block = b"@SEQ_ID\nGATTACAGATTACAGATTACAGATTACAGATTACA\n+\nIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII\n"
    with p.open("wb") as f:
        for _ in range(65_000):  # ~5 MiB
            f.write(block)
    return p


class TestRoundTrip:
    def test_small_file(self, tmp_plaintext: Path, tmp_path: Path) -> None:
        enc_out = tmp_path / "sample.vcf.gvf"
        dec_out = tmp_path / "sample.vcf.decoded"

        enc_res = encrypt_file(
            input_path=tmp_plaintext,
            output_path=enc_out,
            passphrase=TEST_PASSPHRASE,
            params=TEST_PARAMS,
        )
        assert enc_res.input_bytes == tmp_plaintext.stat().st_size
        assert enc_res.output_bytes > enc_res.input_bytes  # overhead added
        assert enc_out.exists()

        dec_res = decrypt_file(
            input_path=enc_out,
            output_path=dec_out,
            passphrase=TEST_PASSPHRASE,
        )
        assert dec_res.output_bytes == enc_res.input_bytes

        # Byte-perfect round-trip
        assert dec_out.read_bytes() == tmp_plaintext.read_bytes()

    def test_large_file_streaming(self, tmp_large_plaintext: Path, tmp_path: Path) -> None:
        # Verifies that files spanning many Crypt4GH segments round-trip.
        enc_out = tmp_path / "big.gvf"
        dec_out = tmp_path / "big.decoded"
        encrypt_file(
            input_path=tmp_large_plaintext,
            output_path=enc_out,
            passphrase=TEST_PASSPHRASE,
            params=TEST_PARAMS,
        )
        decrypt_file(
            input_path=enc_out,
            output_path=dec_out,
            passphrase=TEST_PASSPHRASE,
        )
        assert dec_out.read_bytes() == tmp_large_plaintext.read_bytes()

    def test_empty_file(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.vcf"
        empty.write_bytes(b"")
        enc_out = tmp_path / "empty.gvf"
        dec_out = tmp_path / "empty.decoded"
        encrypt_file(
            input_path=empty, output_path=enc_out, passphrase=TEST_PASSPHRASE, params=TEST_PARAMS
        )
        decrypt_file(input_path=enc_out, output_path=dec_out, passphrase=TEST_PASSPHRASE)
        assert dec_out.read_bytes() == b""


class TestPassphraseSensitivity:
    def test_wrong_passphrase_fails(self, tmp_plaintext: Path, tmp_path: Path) -> None:
        enc_out = tmp_path / "sample.gvf"
        dec_out = tmp_path / "sample.decoded"
        encrypt_file(
            input_path=tmp_plaintext,
            output_path=enc_out,
            passphrase=TEST_PASSPHRASE,
            params=TEST_PARAMS,
        )
        # Any wrong passphrase should produce a decryption error.
        with pytest.raises(ValueError):
            decrypt_file(
                input_path=enc_out, output_path=dec_out, passphrase="wrong passphrase entirely"
            )

    def test_one_bit_wrong_fails(self, tmp_plaintext: Path, tmp_path: Path) -> None:
        enc_out = tmp_path / "sample.gvf"
        dec_out = tmp_path / "sample.decoded"
        encrypt_file(
            input_path=tmp_plaintext,
            output_path=enc_out,
            passphrase="correct horse battery staple",
            params=TEST_PARAMS,
        )
        with pytest.raises(ValueError):
            decrypt_file(
                input_path=enc_out,
                output_path=dec_out,
                passphrase="correct horse battery stapl",  # missing trailing 'e'
            )


class TestTampering:
    def test_modified_ciphertext_fails(self, tmp_plaintext: Path, tmp_path: Path) -> None:
        enc_out = tmp_path / "sample.gvf"
        dec_out = tmp_path / "sample.decoded"
        encrypt_file(
            input_path=tmp_plaintext,
            output_path=enc_out,
            passphrase=TEST_PASSPHRASE,
            params=TEST_PARAMS,
        )
        # Flip a byte deep in the payload (well past the .gvf header and
        # the Crypt4GH header).
        data = bytearray(enc_out.read_bytes())
        flip_at = len(data) - 100  # near-end of file, in the body
        data[flip_at] ^= 0x01
        enc_out.write_bytes(bytes(data))

        with pytest.raises((ValueError, Exception)):
            decrypt_file(
                input_path=enc_out, output_path=dec_out, passphrase=TEST_PASSPHRASE
            )

    def test_truncated_file_fails(self, tmp_plaintext: Path, tmp_path: Path) -> None:
        enc_out = tmp_path / "sample.gvf"
        dec_out = tmp_path / "sample.decoded"
        encrypt_file(
            input_path=tmp_plaintext,
            output_path=enc_out,
            passphrase=TEST_PASSPHRASE,
            params=TEST_PARAMS,
        )
        # Chop off the last 10 bytes.
        data = enc_out.read_bytes()
        enc_out.write_bytes(data[:-10])
        with pytest.raises(Exception):
            decrypt_file(
                input_path=enc_out, output_path=dec_out, passphrase=TEST_PASSPHRASE
            )


class TestPeekAndVerify:
    def test_peek_header(self, tmp_plaintext: Path, tmp_path: Path) -> None:
        enc_out = tmp_path / "sample.gvf"
        result = encrypt_file(
            input_path=tmp_plaintext,
            output_path=enc_out,
            passphrase=TEST_PASSPHRASE,
            params=TEST_PARAMS,
        )
        header = peek_header(enc_out)
        assert header.salt == result.salt
        assert header.scrypt_params == result.scrypt_params

    def test_verify_passes_on_good_file(self, tmp_plaintext: Path, tmp_path: Path) -> None:
        enc_out = tmp_path / "sample.gvf"
        encrypt_file(
            input_path=tmp_plaintext,
            output_path=enc_out,
            passphrase=TEST_PASSPHRASE,
            params=TEST_PARAMS,
        )
        verify_file(enc_out, TEST_PASSPHRASE)  # should not raise

    def test_verify_fails_on_tampered_file(
        self, tmp_plaintext: Path, tmp_path: Path
    ) -> None:
        enc_out = tmp_path / "sample.gvf"
        encrypt_file(
            input_path=tmp_plaintext,
            output_path=enc_out,
            passphrase=TEST_PASSPHRASE,
            params=TEST_PARAMS,
        )
        data = bytearray(enc_out.read_bytes())
        data[len(data) - 100] ^= 0x01
        enc_out.write_bytes(bytes(data))
        with pytest.raises(Exception):
            verify_file(enc_out, TEST_PASSPHRASE)


class TestExtractC4gh:
    def test_extract_and_decrypt_with_external_keys(
        self, tmp_plaintext: Path, tmp_path: Path
    ) -> None:
        enc_out = tmp_path / "sample.gvf"
        encrypt_file(
            input_path=tmp_plaintext,
            output_path=enc_out,
            passphrase=TEST_PASSPHRASE,
            params=TEST_PARAMS,
        )
        c4gh_out = tmp_path / "sample.c4gh"
        sec_out = tmp_path / "sample.sec.hex"
        pub_out = tmp_path / "sample.pub.hex"
        header = extract_c4gh(
            input_path=enc_out,
            output_c4gh_path=c4gh_out,
            output_seckey_path=sec_out,
            output_pubkey_path=pub_out,
            passphrase=TEST_PASSPHRASE,
        )
        assert header is not None
        assert c4gh_out.exists()
        assert sec_out.exists()
        assert pub_out.exists()
        # The secret and public key files should contain 64-char hex + newline
        sec_hex = sec_out.read_text(encoding="ascii").strip()
        pub_hex = pub_out.read_text(encoding="ascii").strip()
        assert len(sec_hex) == 64
        assert len(pub_hex) == 64
        # Public key should match derivation from the secret
        seckey = bytes.fromhex(sec_hex)
        derived_pub = pubkey_from_seckey(seckey)
        assert derived_pub.hex() == pub_hex

        # Decrypt the extracted .c4gh using the raw secret key via
        # crypt4gh.lib directly — proves interop with standard tools.
        import crypt4gh.lib  # deferred import so this stays local to the test
        dec_out = tmp_path / "sample.decoded"
        with c4gh_out.open("rb") as cin, dec_out.open("wb") as dout:
            crypt4gh.lib.decrypt(
                keys=[(0, seckey, None)],
                infile=cin,
                outfile=dout,
            )
        assert dec_out.read_bytes() == tmp_plaintext.read_bytes()


class TestSaltBehavior:
    def test_different_salts_per_encryption(
        self, tmp_plaintext: Path, tmp_path: Path
    ) -> None:
        # Two encryptions of the same plaintext with same passphrase
        # should produce different ciphertexts due to fresh salt.
        out1 = tmp_path / "a.gvf"
        out2 = tmp_path / "b.gvf"
        encrypt_file(
            input_path=tmp_plaintext,
            output_path=out1,
            passphrase=TEST_PASSPHRASE,
            params=TEST_PARAMS,
        )
        encrypt_file(
            input_path=tmp_plaintext,
            output_path=out2,
            passphrase=TEST_PASSPHRASE,
            params=TEST_PARAMS,
        )
        assert out1.read_bytes() != out2.read_bytes()

    def test_explicit_salt_respected(
        self, tmp_plaintext: Path, tmp_path: Path
    ) -> None:
        fixed_salt = os.urandom(32)
        out = tmp_path / "x.gvf"
        res = encrypt_file(
            input_path=tmp_plaintext,
            output_path=out,
            passphrase=TEST_PASSPHRASE,
            params=TEST_PARAMS,
            salt=fixed_salt,
        )
        assert res.salt == fixed_salt
        assert peek_header(out).salt == fixed_salt

    def test_wrong_salt_length_rejected(
        self, tmp_plaintext: Path, tmp_path: Path
    ) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_file(
                input_path=tmp_plaintext,
                output_path=tmp_path / "x.gvf",
                passphrase=TEST_PASSPHRASE,
                params=TEST_PARAMS,
                salt=b"\x00" * 16,
            )
