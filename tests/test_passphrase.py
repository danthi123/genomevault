"""Tests for genomevault.passphrase — strength evaluation + prompting."""

from __future__ import annotations

from genomevault.passphrase import Strength, evaluate


class TestEvaluate:
    def test_empty_is_catastrophic(self) -> None:
        assert evaluate("").strength is Strength.CATASTROPHIC
        assert evaluate("   ").strength is Strength.CATASTROPHIC

    def test_blocklist_hit_catastrophic(self) -> None:
        for pw in ("password", "PASSWORD", "Password", "12345", "qwerty", "letmein"):
            r = evaluate(pw)
            assert r.strength is Strength.CATASTROPHIC, f"{pw!r}: {r}"

    def test_very_short_is_very_weak(self) -> None:
        assert evaluate("short").strength is Strength.VERY_WEAK
        assert evaluate("abcdefghij").strength is Strength.VERY_WEAK  # 10 chars

    def test_single_long_token_still_very_weak(self) -> None:
        # One "word" at 15 chars -> very weak because word count is 1 and
        # length is below the single-word acceptable floor (16).
        assert evaluate("abcdefghijklmno").strength is Strength.VERY_WEAK  # 15

    def test_single_token_at_16_is_weak_not_very_weak(self) -> None:
        # 16-char single token passes the very-weak gate.  Still WEAK because
        # overall length is under 20.
        assert evaluate("abcdefghijklmnop").strength is Strength.WEAK

    def test_short_multi_word_is_weak(self) -> None:
        # 2 words, 13 chars -> WEAK
        r = evaluate("hello world x")  # 13 chars, 3 "words"
        assert r.strength is Strength.WEAK

    def test_four_words_twenty_chars_is_ok(self) -> None:
        r = evaluate("alpha beta gamma foxy")  # 21 chars
        assert r.strength is Strength.OK

    def test_thirty_chars_strong(self) -> None:
        # 32 chars, 5 words
        r = evaluate("correct horse battery staple six")
        assert r.strength is Strength.STRONG

    def test_fifty_plus_very_strong(self) -> None:
        r = evaluate("the glass wall opens twice each visit and again tomorrow")
        assert r.strength is Strength.VERY_STRONG

    def test_acceptable_flag(self) -> None:
        assert not evaluate("password").acceptable
        assert not evaluate("abc").acceptable
        assert evaluate("alpha beta gamma delta").acceptable
        assert evaluate("a much longer phrase that definitely works").acceptable

    def test_word_count_counting(self) -> None:
        # Multiple spaces collapse
        r = evaluate("hello     world     test     phrase")
        assert r.words == 4

    def test_unicode_passphrase_counted(self) -> None:
        r = evaluate("café wörd 密钥 phrase")
        # All four whitespace-separated runs count as words.
        assert r.words == 4
        # Length in Python str is character count
        assert r.length == len("café wörd 密钥 phrase")
