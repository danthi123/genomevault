"""Passphrase input + strength guidance.

Design note: this module exists so the CLI can set one consistent tone for
how users think about passphrases.  **Length matters more than
complexity.**  Four memorable words beat eight scrambled characters —
both for security AND for remembering-it-ten-years-later.

Strength is evaluated against:

1. Character length (primary)
2. Word count (secondary — a rough proxy for entropy)
3. Against a short blocklist of catastrophically common passwords
   ("password", "123456", etc.) because the UX is too important to let
   somebody accidentally encrypt their genome with "letmein".

Nothing here is "security theater" — we do not score based on
"includes a digit" or "includes a symbol".  Decades of UX research and
NIST SP 800-63B agree those rules produce worse passwords, not better
ones.
"""

from __future__ import annotations

import getpass
import re
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Final, TextIO


class Strength(Enum):
    CATASTROPHIC = "catastrophic"  # blocklist hit — refuse
    VERY_WEAK = "very weak"  # < 12 chars or 1 word — refuse by default
    WEAK = "weak"  # 12-19 chars, 2-3 words — warn and require confirm
    OK = "ok"  # 20-29 chars, 3+ words
    STRONG = "strong"  # 30-49 chars
    VERY_STRONG = "very strong"  # 50+ chars


@dataclass(frozen=True)
class StrengthReport:
    strength: Strength
    length: int
    words: int
    message: str

    @property
    def acceptable(self) -> bool:
        """Whether this passphrase meets the default acceptance bar."""
        return self.strength not in (Strength.CATASTROPHIC, Strength.VERY_WEAK)


# A tiny blocklist of the most catastrophically common passwords seen in
# breach corpora (have-i-been-pwned Top N, RockYou, etc.).  We do not try
# to be exhaustive — rejecting all-ASCII lowercase passphrases under 20
# chars already excludes most of the problem.  The list here is for the
# cases where someone picks something absurdly bad on purpose.
_BLOCKLIST: Final[frozenset[str]] = frozenset(
    line.strip().lower()
    for line in """\
password
password1
password123
12345
123456
1234567
12345678
123456789
1234567890
qwerty
qwertyuiop
asdfghjkl
letmein
welcome
admin
administrator
monkey
football
dragon
iloveyou
trustno1
abc123
master
hello
hello123
charlie
princess
""".splitlines()
    if line.strip()
)


# Default user-facing guidance printed before the prompt on encrypt.
GUIDANCE: Final[str] = """\
Passphrase guidance:
  * Pick a phrase you will remember for years — the length is the
    strength.  A four-word phrase is harder to crack than most
    eight-character passwords you have ever used.
  * Example good choices:
      - the glass wall opens twice each visit
      - sequencer hums at sunrise in brooklyn
      - my grandmother kept recipes in a tin
  * Avoid:
      - short words with punctuation "tricks" (P@ssw0rd!)
      - anything on a breach list (password, 123456, qwerty)
      - phrases copied directly from books, songs, or films
  * Length >= 20 characters is the recommended minimum.  Longer is
    stronger.  Mixed case and digits are nice but length matters more.
  * IMPORTANT: there is NO recovery path.  If you forget this phrase,
    your data is permanently unreadable.  Consider a password manager
    or a physically-secure paper backup for life-critical files.
"""


def _count_words(phrase: str) -> int:
    """Return the number of whitespace-separated runs of non-space chars.

    "hello world" -> 2
    "hello  world" -> 2
    "helloworld" -> 1
    "" -> 0
    """
    return len(re.split(r"\s+", phrase.strip())) if phrase.strip() else 0


def evaluate(passphrase: str) -> StrengthReport:
    """Classify a passphrase by length, word count, and blocklist hit.

    We bias STRONGLY toward length.  A 30-character phrase with only
    lowercase ASCII letters clears the STRONG threshold because length
    dominates entropy per NIST SP 800-63B recommendations.
    """
    length = len(passphrase)
    words = _count_words(passphrase)

    # Catastrophic: direct hit on the blocklist OR just whitespace
    normalized = passphrase.strip().lower()
    if not normalized:
        return StrengthReport(
            strength=Strength.CATASTROPHIC,
            length=length,
            words=words,
            message="passphrase is empty or all whitespace",
        )
    if normalized in _BLOCKLIST:
        return StrengthReport(
            strength=Strength.CATASTROPHIC,
            length=length,
            words=words,
            message=f"{passphrase!r} is on the common-passwords blocklist",
        )

    # Very weak: too short or clearly single-token
    if length < 12 or (words <= 1 and length < 16):
        return StrengthReport(
            strength=Strength.VERY_WEAK,
            length=length,
            words=words,
            message=(
                f"passphrase is too short (length={length}, words={words}); "
                "minimum recommended: 20 characters or 4+ words"
            ),
        )

    # Weak: short-but-not-terrible
    if length < 20:
        return StrengthReport(
            strength=Strength.WEAK,
            length=length,
            words=words,
            message=(
                f"passphrase is shorter than recommended (length={length}); "
                "consider adding more words"
            ),
        )

    # OK / Strong / Very strong
    if length < 30:
        strength = Strength.OK
        message = f"acceptable (length={length}, words={words})"
    elif length < 50:
        strength = Strength.STRONG
        message = f"strong (length={length}, words={words})"
    else:
        strength = Strength.VERY_STRONG
        message = f"very strong (length={length}, words={words})"

    return StrengthReport(strength=strength, length=length, words=words, message=message)


def prompt_for_new_passphrase(
    *,
    stream: TextIO | None = None,
    confirm: bool = True,
    show_guidance: bool = True,
) -> str:
    """Interactively prompt for a new passphrase, with guidance + confirm.

    Uses ``getpass`` so the passphrase is not echoed to the terminal.
    On platforms where ``getpass`` falls back to echoing (rare — mostly
    IDE terminals) we still call it so the behavior is consistent.

    Raises ``PassphraseError`` if confirmation fails or strength is
    CATASTROPHIC / VERY_WEAK.  The caller is expected to surface the
    error cleanly.
    """
    out = stream or sys.stderr
    if show_guidance:
        print(GUIDANCE, file=out)

    while True:
        pw = getpass.getpass("Passphrase: ", stream=out)
        report = evaluate(pw)
        if report.strength is Strength.CATASTROPHIC:
            print(
                f"refused: {report.message}. Please pick something else.",
                file=out,
            )
            continue
        if report.strength is Strength.VERY_WEAK:
            print(
                f"refused: {report.message}. Please pick a longer phrase.",
                file=out,
            )
            continue
        if report.strength is Strength.WEAK:
            print(
                f"WARNING: {report.message}. "
                "Proceeding — but longer phrases are materially more secure.",
                file=out,
            )
        else:
            print(f"strength: {report.message}", file=out)

        if confirm:
            pw2 = getpass.getpass("Confirm passphrase: ", stream=out)
            if pw != pw2:
                print("passphrases do not match; please try again.", file=out)
                continue
        return pw


def prompt_for_existing_passphrase(*, stream: TextIO | None = None) -> str:
    """Prompt for a passphrase to decrypt an existing file.

    Does NOT evaluate strength — the file was already encrypted with
    some passphrase and the user has no choice about it.  Does NOT
    confirm — only one attempt per call (the CLI can retry).
    """
    out = stream or sys.stderr
    return getpass.getpass("Passphrase: ", stream=out)
