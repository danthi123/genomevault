"""Tests for the CLI.  Runs commands in-process via ``cli.main(argv)``."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from genomevault.cli import main

TEST_PASSPHRASE = "the glass wall opens twice each visit"


@pytest.fixture
def sample_vcf(tmp_path: Path) -> Path:
    p = tmp_path / "sample.vcf"
    p.write_text(
        "##fileformat=VCFv4.2\n#CHROM\tPOS\tID\tREF\tALT\n"
        + "\n".join(f"chr1\t{i}\trs{i}\tA\tG" for i in range(100))
        + "\n",
        encoding="ascii",
    )
    return p


def run_with_stdin_pw(argv: list[str], passphrase: str) -> int:
    """Helper: run the CLI with ``--passphrase-stdin`` and feed passphrase."""
    saved_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO(passphrase + "\n")
        return main(argv)
    finally:
        sys.stdin = saved_stdin


class TestEncryptDecrypt:
    def test_roundtrip(self, sample_vcf: Path, tmp_path: Path) -> None:
        enc_out = tmp_path / "sample.vcf.gvf"
        dec_out = tmp_path / "sample.vcf.decoded"

        rc = run_with_stdin_pw(
            [
                "encrypt",
                str(sample_vcf),
                "-o",
                str(enc_out),
                "--passphrase-stdin",
            ],
            TEST_PASSPHRASE,
        )
        assert rc == 0
        assert enc_out.exists()

        rc = run_with_stdin_pw(
            [
                "decrypt",
                str(enc_out),
                "-o",
                str(dec_out),
                "--passphrase-stdin",
            ],
            TEST_PASSPHRASE,
        )
        assert rc == 0
        assert dec_out.read_bytes() == sample_vcf.read_bytes()

    def test_default_output_paths(self, sample_vcf: Path, tmp_path: Path) -> None:
        # encrypt defaults to <input>.gvf
        rc = run_with_stdin_pw(
            ["encrypt", str(sample_vcf), "--passphrase-stdin"],
            TEST_PASSPHRASE,
        )
        assert rc == 0
        gvf = sample_vcf.with_suffix(sample_vcf.suffix + ".gvf")
        assert gvf.exists()

        # decrypt defaults to stripping .gvf
        sample_vcf.unlink()  # remove original to avoid conflict
        rc = run_with_stdin_pw(
            ["decrypt", str(gvf), "--passphrase-stdin"],
            TEST_PASSPHRASE,
        )
        assert rc == 0
        assert sample_vcf.exists()

    def test_refuses_overwrite_without_force(
        self, sample_vcf: Path, tmp_path: Path
    ) -> None:
        enc_out = tmp_path / "sample.vcf.gvf"
        enc_out.write_bytes(b"EXISTING")
        with pytest.raises(SystemExit) as exc:
            run_with_stdin_pw(
                [
                    "encrypt",
                    str(sample_vcf),
                    "-o",
                    str(enc_out),
                    "--passphrase-stdin",
                ],
                TEST_PASSPHRASE,
            )
        assert exc.value.code == 1
        assert enc_out.read_bytes() == b"EXISTING"  # unchanged

    def test_force_overwrite(self, sample_vcf: Path, tmp_path: Path) -> None:
        enc_out = tmp_path / "sample.vcf.gvf"
        enc_out.write_bytes(b"EXISTING")
        rc = run_with_stdin_pw(
            [
                "encrypt",
                str(sample_vcf),
                "-o",
                str(enc_out),
                "--force",
                "--passphrase-stdin",
            ],
            TEST_PASSPHRASE,
        )
        assert rc == 0
        assert enc_out.read_bytes() != b"EXISTING"

    def test_nonexistent_input_fails(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit):
            run_with_stdin_pw(
                [
                    "encrypt",
                    str(tmp_path / "does-not-exist.vcf"),
                    "--passphrase-stdin",
                ],
                TEST_PASSPHRASE,
            )

    def test_weak_passphrase_from_stdin_rejected(self, sample_vcf: Path) -> None:
        with pytest.raises(SystemExit):
            run_with_stdin_pw(
                ["encrypt", str(sample_vcf), "--passphrase-stdin"],
                "short",  # very weak
            )

    def test_blocklisted_passphrase_rejected(self, sample_vcf: Path) -> None:
        with pytest.raises(SystemExit):
            run_with_stdin_pw(
                ["encrypt", str(sample_vcf), "--passphrase-stdin"],
                "password",
            )


class TestInfoVerify:
    def test_info_after_encrypt(
        self, sample_vcf: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        enc_out = tmp_path / "sample.vcf.gvf"
        run_with_stdin_pw(
            ["encrypt", str(sample_vcf), "-o", str(enc_out), "--passphrase-stdin"],
            TEST_PASSPHRASE,
        )

        rc = main(["info", str(enc_out)])
        assert rc == 0
        captured = capsys.readouterr()
        assert "format version: 1" in captured.out
        assert "KDF:            scrypt" in captured.out
        assert "salt (hex):" in captured.out

    def test_verify_good_file(self, sample_vcf: Path, tmp_path: Path) -> None:
        enc_out = tmp_path / "sample.vcf.gvf"
        run_with_stdin_pw(
            ["encrypt", str(sample_vcf), "-o", str(enc_out), "--passphrase-stdin"],
            TEST_PASSPHRASE,
        )
        rc = run_with_stdin_pw(
            ["verify", str(enc_out), "--passphrase-stdin"], TEST_PASSPHRASE
        )
        assert rc == 0

    def test_verify_wrong_passphrase_fails(
        self, sample_vcf: Path, tmp_path: Path
    ) -> None:
        enc_out = tmp_path / "sample.vcf.gvf"
        run_with_stdin_pw(
            ["encrypt", str(sample_vcf), "-o", str(enc_out), "--passphrase-stdin"],
            TEST_PASSPHRASE,
        )
        with pytest.raises(SystemExit):
            run_with_stdin_pw(
                ["verify", str(enc_out), "--passphrase-stdin"],
                "wrong passphrase entirely",
            )

    def test_info_on_non_gvf_fails(
        self, sample_vcf: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit):
            main(["info", str(sample_vcf)])


class TestExtract:
    def test_extract_produces_three_files(
        self, sample_vcf: Path, tmp_path: Path
    ) -> None:
        enc_out = tmp_path / "sample.vcf.gvf"
        run_with_stdin_pw(
            ["encrypt", str(sample_vcf), "-o", str(enc_out), "--passphrase-stdin"],
            TEST_PASSPHRASE,
        )

        extract_dir = tmp_path / "extracted"
        rc = run_with_stdin_pw(
            [
                "extract",
                str(enc_out),
                "-d",
                str(extract_dir),
                "--passphrase-stdin",
            ],
            TEST_PASSPHRASE,
        )
        assert rc == 0
        assert (extract_dir / "sample.vcf.c4gh").exists()
        assert (extract_dir / "sample.vcf.seckey.hex").exists()
        assert (extract_dir / "sample.vcf.pubkey.hex").exists()


class TestVersion:
    def test_version_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert "genomevault" in captured.out

    def test_help_does_not_crash(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert "encrypt" in captured.out
        assert "decrypt" in captured.out
