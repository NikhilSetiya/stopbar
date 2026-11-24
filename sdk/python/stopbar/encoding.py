"""Encoding detector (CS-183, LLD §8.2): flags encoded content in untrusted
input so the session carries the ``decoded`` label.

An injected instruction hidden in base64, hex, Morse, ROT-n or zero-width
characters reads as noise to a human reviewer but not to the model, which
decodes it (the Grok/Bankr pattern, corpus CS-2026-0001). The detector only
adds a label, and labels only restrict, so a miss never loosens anything.

To keep false positives low on ordinary content (addresses, tx hashes,
calldata, ids, emoji), base64 and hex count only when they decode to readable
text, Morse needs a run of real codes, and ROT-n needs a segment that is not
English as written but is under some rotation. ``sdk/typescript/src/encoding.ts``
is a line-for-line port; ``sdk/testdata/encodings.json`` holds the fixtures both
SDKs' tests must agree on.
"""
from __future__ import annotations

import base64
import binascii
import re

KINDS = ("base64", "hex", "morse", "rot", "zero_width")

# Emoji joined by ZWJ (family, flags), a leading BOM and ZWNJ inside non-Latin
# words are legitimate; they are removed before looking for hidden characters.
_EMOJI_ZWJ = re.compile("([\u2600-\u27bf\U0001f000-\U0001faff]\ufe0f?)\u200d(?=[\u2600-\u27bf\U0001f000-\U0001faff])")
_ZWNJ_IN_WORD = re.compile("(?<=[^\x00-\x7f])\u200c(?=[^\x00-\x7f])")
_ZERO_WIDTH = re.compile("[\u200b-\u200d\u2060-\u2064\u180e\ufeff\U000e0000-\U000e007f]")

_B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])")
_HEX = re.compile(r"(?<![0-9A-Za-z])(?:0x)?(?:[0-9a-fA-F]{16,}|(?:[0-9a-fA-F]{2}[ :]){7,}[0-9a-fA-F]{2})(?![0-9A-Za-z])")

_MORSE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f", "--.": "g", "....": "h",
    "..": "i", ".---": "j", "-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o", ".--.": "p",
    "--.-": "q", ".-.": "r", "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
}

# Common English words (3+ letters) plus the vocabulary of wallet-draining
# instructions; ROT-n is flagged when a rotation turns a non-English segment
# into mostly these.
WORDS = frozenset("""
the and for are but not you all any can her was one our out has him his how new now old see two way who did
its let put say she too use this that with have from they will would there their what about which when make
like time just know take into your some could them than then look only come over think also back after work
first well even want because these give most here been were said each more other many such very must should
please send transfer ignore previous instructions instruction wallet token tokens funds money address
immediately balance approve execute system prompt user assistant command following below above private key
keys secret password admin account pay payment eth usdc bitcoin crypto swap buy sell reply tell everything
contract call new rules forget disregard
""".split())


def detect(text: str) -> list[str]:
    """The encodings found in text, as a sorted list drawn from KINDS."""
    found = set()
    visible = _ZWNJ_IN_WORD.sub("", _EMOJI_ZWJ.sub(r"\1", text.removeprefix("\ufeff")))
    if _ZERO_WIDTH.search(visible):
        found.add("zero_width")
    for m in _B64.finditer(text):
        s = m.group().rstrip("=").replace("-", "+").replace("_", "/")
        if len(s) % 4 == 1:
            continue
        try:
            raw = base64.b64decode(s + "=" * (-len(s) % 4))
        except (binascii.Error, ValueError):
            continue
        if _readable(raw):
            found.add("base64")
            break
    for m in _HEX.finditer(text):
        h = re.sub(r"[ :]", "", m.group().removeprefix("0x"))
        if _readable(bytes.fromhex(h[: len(h) // 2 * 2])):
            found.add("hex")
            break
    if _morse(text):
        found.add("morse")
    if _rot(text):
        found.add("rot")
    return sorted(found)


def _readable(raw: bytes) -> bool:
    """Decoded bytes that are text: printable ASCII, mostly letters, and not one
    repeated byte (test addresses like 0x5555... decode to "UUUU")."""
    n = len(raw)
    if n < 6 or len(set(raw)) < 5:
        return False
    printable = sum(1 for b in raw if 0x20 <= b <= 0x7E or b in (9, 10, 13))
    letters = sum(1 for b in raw if 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A)
    return printable >= 0.95 * n and letters >= 0.5 * n


def _morse(text: str) -> bool:
    """A run of at least five valid Morse codes, using both dots and dashes."""
    norm = text.translate(str.maketrans("\u00b7\u2022\u2013\u2014\u2212_", "..----"))
    norm = re.sub(r"[/|]", " / ", norm)
    run: list[str] = []
    for tok in norm.split() + [""]:
        if tok in _MORSE:
            run.append(tok)
        elif tok == "/":
            continue
        else:
            joined = "".join(run)
            if len(run) >= 5 and "." in joined and "-" in joined:
                return True
            run = []
    return False


def _rot(text: str) -> bool:
    """A segment of 4+ distinct words that is not English as written but is
    under some rotation n in 1..25 (ROT13 being the usual one)."""
    for seg in re.split(r"[\n\r.!?;:\"()\[\]{}<>]+", text):
        words = list(dict.fromkeys(w.lower() for w in re.findall(r"[A-Za-z]+", seg) if len(w) >= 3))
        if len(words) < 4 or _hits(words) >= 0.2 * len(words):
            continue
        for n in range(1, 26):
            rotated = ["".join(chr((ord(c) - 97 + n) % 26 + 97) for c in w) for w in words]
            hits = _hits(rotated)
            if hits >= 3 and hits >= 0.5 * len(words):
                return True
    return False


def _hits(words: list[str]) -> int:
    return sum(1 for w in words if w in WORDS)
