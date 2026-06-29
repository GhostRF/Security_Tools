"""Safe, non-executing decoding and decompression functions."""

from __future__ import annotations

import ast
import base64
import binascii
import bz2
import hashlib
import lzma
import re
import zlib
from html import unescape
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

_QUOTED_LITERAL = (
    r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')'''
)

_CONCATENATION_PATTERN = re.compile(
    rf"(?P<expression>"
    rf"{_QUOTED_LITERAL}"
    rf"(?:\s*\+\s*{_QUOTED_LITERAL})+"
    rf")"
)

_LITERAL_PATTERN = re.compile(_QUOTED_LITERAL)


class OutputLimitError(Exception):
    """Raised when decompressed content exceeds a configured limit."""


def _remove_whitespace(value: str) -> str:
    """Remove whitespace from an encoded value."""

    return "".join(value.split())


def _add_base64_padding(value: str) -> str:
    """Add missing Base64 padding."""

    return value + ("=" * ((4 - len(value) % 4) % 4))


def _warning_candidate(
    transform: str,
    evidence: str,
    warning: str,
) -> TransformCandidate:
    """Create a non-output candidate that carries a visible warning."""

    return TransformCandidate(
        transform=transform,
        decoded=b"",
        confidence=0,
        evidence=evidence,
        warnings=[warning],
    )


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
        if character.isprintable()
        or character in "\r\n\t"
    )

    return printable_characters / len(text)


def bytes_to_text(
    data: bytes,
) -> Tuple[str, str, List[str]]:
    """Decode bytes for inspection without executing the content."""

    warnings: List[str] = []

    if data.startswith(b"\xff\xfe"):
        try:
            return (
                data.decode("utf-16le"),
                "utf-16le",
                warnings,
            )
        except UnicodeDecodeError:
            pass

    if data.startswith(b"\xfe\xff"):
        try:
            return (
                data.decode("utf-16be"),
                "utf-16be",
                warnings,
            )
        except UnicodeDecodeError:
            pass

    if len(data) >= 4:
        pair_count = max(1, len(data) // 2)
        odd_null_ratio = (
            data[1::2].count(0) / pair_count
        )
        even_null_ratio = (
            data[0::2].count(0) / pair_count
        )

        if odd_null_ratio >= 0.30:
            try:
                return (
                    data.decode("utf-16le"),
                    "utf-16le",
                    warnings,
                )
            except UnicodeDecodeError:
                pass

        if even_null_ratio >= 0.30:
            try:
                return (
                    data.decode("utf-16be"),
                    "utf-16be",
                    warnings,
                )
            except UnicodeDecodeError:
                pass

    try:
        return (
            data.decode("utf-8"),
            "utf-8",
            warnings,
        )
    except UnicodeDecodeError:
        warnings.append(
            "Content was not valid UTF-8. "
            "Replacement characters were used."
        )

        return (
            data.decode(
                "utf-8",
                errors="replace",
            ),
            "utf-8-replace",
            warnings,
        )


def decode_base64_text(
    text: str,
) -> List[TransformCandidate]:
    """Decode a complete Base64 text stage."""

    candidate_text = _remove_whitespace(
        text.strip()
    )

    if len(candidate_text) < 8:
        return []

    if not _BASE64_PATTERN.fullmatch(
        candidate_text
    ):
        return []

    padded = _add_base64_padding(
        candidate_text
    )

    candidates: List[TransformCandidate] = []

    decoding_modes = (
        ("base64", None, 90),
        ("base64-url", b"-_", 85),
    )

    for (
        transform_name,
        alternate_characters,
        confidence,
    ) in decoding_modes:
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
                    "The complete stage matched a Base64 "
                    "alphabet and decoded successfully using "
                    "strict validation."
                ),
            )
        )

    unique_candidates = {}

    for candidate in candidates:
        unique_candidates.setdefault(
            candidate.decoded,
            candidate,
        )

    return list(unique_candidates.values())


def decode_powershell_encoded_command(
    text: str,
) -> List[TransformCandidate]:
    """Decode PowerShell EncodedCommand arguments as UTF-16LE."""

    candidates: List[TransformCandidate] = []

    for match in (
        _POWERSHELL_ENCODED_COMMAND_PATTERN.finditer(
            text
        )
    ):
        encoded_payload = _add_base64_padding(
            match.group("payload")
        )

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
                transform=(
                    "powershell-encoded-command"
                ),
                decoded=decoded,
                confidence=100,
                evidence=(
                    "A PowerShell EncodedCommand "
                    "argument was observed and its "
                    "payload decoded successfully as "
                    "UTF-16LE."
                ),
            )
        )

    return candidates


def decode_hex_text(
    text: str,
) -> List[TransformCandidate]:
    """Decode a complete hexadecimal stage."""

    candidate_text = _remove_whitespace(
        text.strip()
    )

    if not _HEX_PATTERN.fullmatch(
        candidate_text
    ):
        return []

    if candidate_text.lower().startswith("0x"):
        candidate_text = candidate_text[2:]

    if (
        len(candidate_text) < 8
        or len(candidate_text) % 2 != 0
    ):
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
                "The complete stage contained an "
                "even-length hexadecimal value and "
                "decoded successfully."
            ),
        )
    ]


def decode_url_percent(
    text: str,
) -> List[TransformCandidate]:
    """Decode percent-encoded bytes without network activity."""

    if not _PERCENT_PATTERN.search(text):
        return []

    try:
        decoded = unquote_to_bytes(text)
    except (UnicodeError, ValueError):
        return []

    original = text.encode(
        "utf-8",
        errors="replace",
    )

    if decoded == original:
        return []

    return [
        TransformCandidate(
            transform="url-percent",
            decoded=decoded,
            confidence=85,
            evidence=(
                "The stage contained percent-encoded "
                "byte sequences that produced different "
                "decoded content."
            ),
        )
    ]


def decode_html_entities(
    text: str,
) -> List[TransformCandidate]:
    """Decode HTML character entities."""

    decoded = unescape(text)

    if decoded == text:
        return []

    return [
        TransformCandidate(
            transform="html-entity",
            decoded=decoded.encode("utf-8"),
            confidence=80,
            evidence=(
                "HTML character entities were present "
                "and produced different decoded content."
            ),
        )
    ]


def reconstruct_string_concatenation(
    text: str,
) -> List[TransformCandidate]:
    """Safely join simple quoted strings connected by plus signs.

    This function performs literal reconstruction only. It does not
    evaluate variables, functions, expressions, or executable code.
    """

    matches = list(
        _CONCATENATION_PATTERN.finditer(text)
    )

    if not matches:
        return []

    reconstructed = text
    replacements = 0

    for match in reversed(matches):
        expression = match.group("expression")
        literals = _LITERAL_PATTERN.findall(
            expression
        )

        values: List[str] = []

        for literal in literals:
            try:
                value = ast.literal_eval(literal)
            except (SyntaxError, ValueError):
                values = []
                break

            if not isinstance(value, str):
                values = []
                break

            values.append(value)

        if len(values) < 2:
            continue

        joined = "".join(values)

        reconstructed = (
            reconstructed[:match.start()]
            + joined
            + reconstructed[match.end():]
        )

        replacements += 1

    if replacements == 0 or reconstructed == text:
        return []

    return [
        TransformCandidate(
            transform="string-concatenation",
            decoded=reconstructed.encode("utf-8"),
            confidence=75,
            evidence=(
                "Two or more quoted string literals "
                "joined with plus signs were safely "
                "reconstructed without evaluating code."
            ),
        )
    ]


def _decompress_zlib_limited(
    data: bytes,
    window_bits: int,
    maximum_output_bytes: int,
) -> bytes:
    """Decompress gzip or zlib while enforcing an output limit."""

    decompressor = zlib.decompressobj(
        window_bits
    )

    output = decompressor.decompress(
        data,
        maximum_output_bytes + 1,
    )

    if (
        len(output) > maximum_output_bytes
        or decompressor.unconsumed_tail
    ):
        raise OutputLimitError

    if not decompressor.eof:
        raise ValueError(
            "The compressed stream was incomplete "
            "or malformed."
        )

    remaining = (
        maximum_output_bytes + 1 - len(output)
    )

    if remaining > 0:
        output += decompressor.flush(remaining)

    if len(output) > maximum_output_bytes:
        raise OutputLimitError

    return output


def decode_gzip_bytes(
    data: bytes,
    maximum_output_bytes: int,
) -> List[TransformCandidate]:
    """Decode a gzip stream identified by its magic bytes."""

    if not data.startswith(b"\x1f\x8b"):
        return []

    evidence = (
        "The stage began with the gzip magic bytes "
        "1F 8B."
    )

    try:
        decoded = _decompress_zlib_limited(
            data,
            16 + zlib.MAX_WBITS,
            maximum_output_bytes,
        )
    except OutputLimitError:
        return [
            _warning_candidate(
                "gzip",
                evidence,
                "Gzip output exceeded the configured "
                "maximum decoded size.",
            )
        ]
    except (ValueError, zlib.error) as error:
        return [
            _warning_candidate(
                "gzip",
                evidence,
                f"Malformed gzip stream: {error}",
            )
        ]

    return [
        TransformCandidate(
            transform="gzip",
            decoded=decoded,
            confidence=100,
            evidence=evidence,
        )
    ]


def _looks_like_zlib(data: bytes) -> bool:
    """Return whether bytes have a valid-looking zlib header."""

    if len(data) < 2:
        return False

    compression_method = data[0] & 0x0F
    header_value = (
        data[0] << 8
    ) + data[1]

    return (
        compression_method == 8
        and header_value % 31 == 0
    )


def decode_zlib_bytes(
    data: bytes,
    maximum_output_bytes: int,
) -> List[TransformCandidate]:
    """Decode a zlib stream after validating its header."""

    if not _looks_like_zlib(data):
        return []

    evidence = (
        "The stage contained a valid-looking zlib "
        "header using the DEFLATE compression method."
    )

    try:
        decoded = _decompress_zlib_limited(
            data,
            zlib.MAX_WBITS,
            maximum_output_bytes,
        )
    except OutputLimitError:
        return [
            _warning_candidate(
                "zlib",
                evidence,
                "Zlib output exceeded the configured "
                "maximum decoded size.",
            )
        ]
    except (ValueError, zlib.error) as error:
        return [
            _warning_candidate(
                "zlib",
                evidence,
                f"Malformed zlib stream: {error}",
            )
        ]

    return [
        TransformCandidate(
            transform="zlib",
            decoded=decoded,
            confidence=95,
            evidence=evidence,
        )
    ]


def decode_bzip2_bytes(
    data: bytes,
    maximum_output_bytes: int,
) -> List[TransformCandidate]:
    """Decode a Bzip2 stream identified by its BZh signature."""

    if not data.startswith(b"BZh"):
        return []

    evidence = (
        "The stage began with the Bzip2 BZh signature."
    )

    decompressor = bz2.BZ2Decompressor()

    try:
        decoded = decompressor.decompress(
            data,
            max_length=maximum_output_bytes + 1,
        )
    except OSError as error:
        return [
            _warning_candidate(
                "bzip2",
                evidence,
                f"Malformed Bzip2 stream: {error}",
            )
        ]

    if len(decoded) > maximum_output_bytes:
        return [
            _warning_candidate(
                "bzip2",
                evidence,
                "Bzip2 output exceeded the configured "
                "maximum decoded size.",
            )
        ]

    if not decompressor.eof:
        if not decompressor.needs_input:
            return [
                _warning_candidate(
                    "bzip2",
                    evidence,
                    "Bzip2 output exceeded the configured "
                    "maximum decoded size.",
                )
            ]

        return [
            _warning_candidate(
                "bzip2",
                evidence,
                "The Bzip2 stream was incomplete.",
            )
        ]

    return [
        TransformCandidate(
            transform="bzip2",
            decoded=decoded,
            confidence=100,
            evidence=evidence,
        )
    ]


def decode_lzma_bytes(
    data: bytes,
    maximum_output_bytes: int,
) -> List[TransformCandidate]:
    """Decode an XZ/LZMA stream identified by the XZ signature."""

    if not data.startswith(b"\xfd7zXZ\x00"):
        return []

    evidence = (
        "The stage began with the XZ container "
        "signature used for LZMA-compressed data."
    )

    decompressor = lzma.LZMADecompressor(
        format=lzma.FORMAT_AUTO
    )

    try:
        decoded = decompressor.decompress(
            data,
            max_length=maximum_output_bytes + 1,
        )
    except lzma.LZMAError as error:
        return [
            _warning_candidate(
                "lzma-xz",
                evidence,
                f"Malformed XZ/LZMA stream: {error}",
            )
        ]

    if len(decoded) > maximum_output_bytes:
        return [
            _warning_candidate(
                "lzma-xz",
                evidence,
                "XZ/LZMA output exceeded the configured "
                "maximum decoded size.",
            )
        ]

    if not decompressor.eof:
        if not decompressor.needs_input:
            return [
                _warning_candidate(
                    "lzma-xz",
                    evidence,
                    "XZ/LZMA output exceeded the configured "
                    "maximum decoded size.",
                )
            ]

        return [
            _warning_candidate(
                "lzma-xz",
                evidence,
                "The XZ/LZMA stream was incomplete.",
            )
        ]

    return [
        TransformCandidate(
            transform="lzma-xz",
            decoded=decoded,
            confidence=100,
            evidence=evidence,
        )
    ]
