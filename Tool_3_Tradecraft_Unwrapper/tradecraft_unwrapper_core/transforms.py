"""Safe, non-executing decoding functions."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import List, Tuple
from urllib.parse import unquote_to_bytes

from .models import TransformCandidate


_BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_HEX_PATTERN = re.compile(r"^(?:0x)?[0-9A-Fa-f]+$")
_PERCENT_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")

_POWERSHELL_ENCODED_COMMAND_PATTERN = re.compile(
    r"(?i)"
    r"\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b"
    r"[^\r\n]{0,300}?"
    r"(?:-|/)(?:e|en|enc|enco|encod|encodedcommand)\s+"
    r"(?P<payload>[A-Za-z0-9+/=_-]{8,})"
)


def _remove_whitespace(value: str) -> str:
    """Remove whitespace from an encoded value."""

    return "".join(value.split())


def _add_base64_padding(value: str) -> str:
    """Add missing Base64 padding without changing existing content."""

    return value + ("=" * ((4 - len(value) % 4) % 4))


def decode_base64_text(text: str) -> List[TransformCandidate]:
    """Decode a complete stage that appears to contain Base64 text.

    The function uses strict Base64 validation and never executes the result.
    """

    candidate_text = _remove_whitespace(text.strip())

    if len(candidate_text) < 8:
        return []

    if not _BASE64_PATTERN.fullmatch(candidate_text):
        return []

    padded = _add_base64_padding(candidate_text)
    candidates: List[TransformCandidate] = []

    decoding_modes = (
        ("base64", None, 90),
        ("base64-url", b"-_", 85),
    )

    for transform_name, alternate_characters, confidence in decoding_modes:
        try:
            decoded = base64.b64decode(
                padded,
                altchars=alternate_characters,
                validate=True,
            )
        except (binascii.Error, ValueError):
            continue

        if not decoded:
            continue

        candidates.append(
            TransformCandidate(
                transform=transform_name,
                decoded=decoded,
                confidence=confidence,
                evidence=(
                    "The complete stage matched a Base64 alphabet and "
                    "decoded successfully using strict validation."
                ),
            )
        )

    unique_candidates = {}
    for candidate in candidates:
        unique_candidates.setdefault(candidate.decoded, candidate)

    return list(unique_candidates.values())


def decode_powershell_encoded_command(
    text: str,
) -> List[TransformCandidate]:
    """Extract and decode PowerShell EncodedCommand arguments.

    PowerShell EncodedCommand content is normally Base64-encoded UTF-16LE.
    The decoded bytes are returned but never executed.
    """

    candidates: List[TransformCandidate] = []

    for match in _POWERSHELL_ENCODED_COMMAND_PATTERN.finditer(text):
        encoded_payload = _add_base64_padding(match.group("payload"))

        try:
            decoded = base64.b64decode(
                encoded_payload,
                altchars=b"-_",
                validate=True,
            )
        except (binascii.Error, ValueError):
            continue

        if not decoded or len(decoded) % 2 != 0:
            continue

        try:
            decoded.decode("utf-16le")
        except UnicodeDecodeError:
            continue

        candidates.append(
            TransformCandidate(
                transform="powershell-encoded-command",
                decoded=decoded,
                confidence=100,
                evidence=(
                    "A PowerShell EncodedCommand argument was observed and "
                    "its payload decoded successfully as UTF-16LE."
                ),
            )
        )

    return candidates


def decode_hex_text(text: str) -> List[TransformCandidate]:
    """Decode a complete hexadecimal stage."""

    candidate_text = _remove_whitespace(text.strip())

    if not _HEX_PATTERN.fullmatch(candidate_text):
        return []

    if candidate_text.lower().startswith("0x"):
        candidate_text = candidate_text[2:]

    if len(candidate_text) < 8 or len(candidate_text) % 2 != 0:
        return []

    try:
        decoded = bytes.fromhex(candidate_text)
    except ValueError:
        return []

    if not decoded:
        return []

    return [
        TransformCandidate(
            transform="hex",
            decoded=decoded,
            confidence=90,
            evidence=(
                "The complete stage contained an even-length hexadecimal "
                "value and decoded successfully."
            ),
        )
    ]


def decode_url_percent(text: str) -> List[TransformCandidate]:
    """Decode percent-encoded bytes without accessing the referenced URL."""

    if not _PERCENT_PATTERN.search(text):
        return []

    try:
        decoded = unquote_to_bytes(text)
    except (UnicodeError, ValueError):
        return []

    original = text.encode("utf-8", errors="replace")

    if decoded == original:
        return []

    return [
        TransformCandidate(
            transform="url-percent",
            decoded=decoded,
            confidence=85,
            evidence=(
                "The stage contained percent-encoded byte sequences that "
                "produced different decoded content."
            ),
        )
    ]



def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 digest of a byte sequence."""

    return hashlib.sha256(data).hexdigest()


def printable_ratio(text: str) -> float:
    """Calculate the proportion of printable text characters."""

    if not text:
        return 1.0

    printable_characters = sum(
        1
        for character in text
        if character.isprintable() or character in "\r\n\t"
    )

    return printable_characters / len(text)


def bytes_to_text(data: bytes) -> Tuple[str, str, List[str]]:
    """Decode bytes for inspection without executing the content.

    UTF-16 byte patterns are checked before UTF-8 because PowerShell
    EncodedCommand commonly uses UTF-16LE.
    """

    warnings: List[str] = []

    if data.startswith(b"\xff\xfe"):
        try:
            return data.decode("utf-16le"), "utf-16le", warnings
        except UnicodeDecodeError:
            pass

    if data.startswith(b"\xfe\xff"):
        try:
            return data.decode("utf-16be"), "utf-16be", warnings
        except UnicodeDecodeError:
            pass

    if len(data) >= 4:
        pair_count = max(1, len(data) // 2)
        odd_null_ratio = data[1::2].count(0) / pair_count
        even_null_ratio = data[0::2].count(0) / pair_count

        if odd_null_ratio >= 0.30:
            try:
                return data.decode("utf-16le"), "utf-16le", warnings
            except UnicodeDecodeError:
                pass

        if even_null_ratio >= 0.30:
            try:
                return data.decode("utf-16be"), "utf-16be", warnings
            except UnicodeDecodeError:
                pass

    try:
        return data.decode("utf-8"), "utf-8", warnings
    except UnicodeDecodeError:
        warnings.append(
            "Content was not valid UTF-8. Replacement characters were used."
        )
        return (
            data.decode("utf-8", errors="replace"),
            "utf-8-replace",
            warnings,
        )
