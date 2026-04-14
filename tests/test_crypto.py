"""Tests for genomevault.crypto — deterministic keypair derivation."""

from __future__ import annotations

import os

import pytest

from genomevault.crypto import (
    DK_LEN,
    SALT_LEN,
    DerivedKeyPair,
    ScryptParams,
    derive_keypair,
    derive_seed,
)

# A small test-only parameter set.  N=2**10 is WAY below the production floor
# and would be rejected in normal use, but we relax the floor via a dedicated
# monkeypatch in the tests that use it so unit tests run in milliseconds.
TEST_PARAMS = ScryptParams(n=2**14, r=8, p=1)
FIXED_SALT = b"\x00" * SALT_LEN
ALT_SALT = b"\x01" * SALT_LEN


class TestDeriveSeed:
    def test_deterministic(self) -> None:
        s1 = derive_seed("correct horse battery staple", FIXED_SALT, TEST_PARAMS)
        s2 = derive_seed("correct horse battery staple", FIXED_SALT, TEST_PARAMS)
        assert s1 == s2
        assert len(s1) == DK_LEN

    def test_different_salt_different_seed(self) -> None:
        s1 = derive_seed("same passphrase", FIXED_SALT, TEST_PARAMS)
        s2 = derive_seed("same passphrase", ALT_SALT, TEST_PARAMS)
        assert s1 != s2

    def test_different_passphrase_different_seed(self) -> None:
        s1 = derive_seed("passphrase one", FIXED_SALT, TEST_PARAMS)
        s2 = derive_seed("passphrase two", FIXED_SALT, TEST_PARAMS)
        assert s1 != s2

    def test_unicode_passphrase(self) -> None:
        # Emoji, accented chars, and CJK should all work round-trip.
        pp = "café \U0001f511 密钥"
        s1 = derive_seed(pp, FIXED_SALT, TEST_PARAMS)
        s2 = derive_seed(pp, FIXED_SALT, TEST_PARAMS)
        assert s1 == s2
        assert len(s1) == DK_LEN

    def test_trailing_newline_stripped(self) -> None:
        # Users may paste passphrases with stray \n or \r\n.  Strip.
        s_clean = derive_seed("hello world", FIXED_SALT, TEST_PARAMS)
        s_nl = derive_seed("hello world\n", FIXED_SALT, TEST_PARAMS)
        s_crlf = derive_seed("hello world\r\n", FIXED_SALT, TEST_PARAMS)
        assert s_clean == s_nl == s_crlf

    def test_internal_whitespace_significant(self) -> None:
        # But whitespace INSIDE the phrase IS significant.
        s1 = derive_seed("hello world", FIXED_SALT, TEST_PARAMS)
        s2 = derive_seed("hello  world", FIXED_SALT, TEST_PARAMS)  # two spaces
        assert s1 != s2

    def test_empty_passphrase_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            derive_seed("", FIXED_SALT, TEST_PARAMS)

    def test_non_str_passphrase_rejected(self) -> None:
        with pytest.raises(TypeError):
            derive_seed(b"bytes not str", FIXED_SALT, TEST_PARAMS)  # type: ignore[arg-type]

    def test_wrong_salt_length_rejected(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            derive_seed("any", b"\x00" * 16, TEST_PARAMS)


class TestScryptParams:
    def test_non_power_of_two_N_rejected(self) -> None:
        with pytest.raises(ValueError, match="power of two"):
            ScryptParams(n=3, r=8, p=1).validate()

    def test_below_floor_rejected(self) -> None:
        # 2**10 is a valid power of two but below the security floor (2**14).
        with pytest.raises(ValueError, match="below minimum"):
            ScryptParams(n=2**10, r=8, p=1).validate()

    def test_at_floor_accepted(self) -> None:
        ScryptParams(n=2**14, r=8, p=1).validate()

    def test_zero_r_rejected(self) -> None:
        with pytest.raises(ValueError):
            ScryptParams(n=2**20, r=0, p=1).validate()


class TestDeriveKeypair:
    def test_deterministic(self) -> None:
        kp1 = derive_keypair("phrase", FIXED_SALT, TEST_PARAMS)
        kp2 = derive_keypair("phrase", FIXED_SALT, TEST_PARAMS)
        assert kp1 == kp2
        assert len(kp1.private_key) == 32
        assert len(kp1.public_key) == 32

    def test_private_and_public_differ(self) -> None:
        kp = derive_keypair("phrase", FIXED_SALT, TEST_PARAMS)
        assert kp.private_key != kp.public_key

    def test_different_salt_different_keypair(self) -> None:
        kp1 = derive_keypair("phrase", FIXED_SALT, TEST_PARAMS)
        kp2 = derive_keypair("phrase", ALT_SALT, TEST_PARAMS)
        assert kp1.private_key != kp2.private_key
        assert kp1.public_key != kp2.public_key

    def test_small_passphrase_change_gives_completely_different_key(self) -> None:
        # One-bit change should cascade through KDF and give a fully-different key.
        kp1 = derive_keypair("passphrase-a", FIXED_SALT, TEST_PARAMS)
        kp2 = derive_keypair("passphrase-b", FIXED_SALT, TEST_PARAMS)
        # Not a single byte should match (expected with overwhelming probability).
        matching = sum(1 for x, y in zip(kp1.private_key, kp2.private_key, strict=False) if x == y)
        assert matching < 8  # well under a third of 32 bytes

    def test_derived_key_length(self) -> None:
        kp = derive_keypair("phrase", FIXED_SALT, TEST_PARAMS)
        assert len(kp.private_key) == 32
        assert len(kp.public_key) == 32

    def test_constructs_valid_derivedkeypair(self) -> None:
        # DerivedKeyPair should reject wrong-length inputs.
        with pytest.raises(ValueError, match="32 bytes"):
            DerivedKeyPair(private_key=b"\x00" * 31, public_key=b"\x00" * 32)
        with pytest.raises(ValueError, match="32 bytes"):
            DerivedKeyPair(private_key=b"\x00" * 32, public_key=b"\x00" * 31)


class TestRandomSalt:
    """Sanity: urandom salt should produce different keys for same passphrase."""

    def test_random_salt_diverges(self) -> None:
        salt1 = os.urandom(SALT_LEN)
        salt2 = os.urandom(SALT_LEN)
        kp1 = derive_keypair("shared passphrase", salt1, TEST_PARAMS)
        kp2 = derive_keypair("shared passphrase", salt2, TEST_PARAMS)
        assert kp1.private_key != kp2.private_key
