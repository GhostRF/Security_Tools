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


def _base64_output_size(value: str) -> int:
    """Return the exact decoded size of padded Base64 text."""

    padded = _add_base64_padding(value)
    padding = len(padded) - len(
        padded.rstrip("=")
    )

    return (
        (len(padded) // 4) * 3
        - padding
    )


def _utf8_size(text: str) -> int:
    """Return the UTF-8 byte size of text."""

    return len(
        text.encode(
            "utf-8",
            errors="replace",
        )
    )


def _percent_decoded_size(text: str) -> int:
    """Calculate URL-percent output size without decoding it."""

    size = 0
    index = 0

    while index < len(text):
        if (
            text[index] == "%"
            and index + 2 < len(text)
            and all(
                character in "0123456789abcdefABCDEF"
                for character in text[
                    index + 1:index + 3
                ]
            )
        ):
            size += 1
            index += 3
            continue

        size += len(
            text[index].encode(
                "utf-8",
                errors="replace",
            )
        )
        index += 1

    return size


def _output_limit_candidate(
    transform: str,
    evidence: str,
    estimated_size: int,
    maximum_output_bytes: int,
) -> TransformCandidate:
    """Create a warning when output would exceed its limit."""

    return _warning_candidate(
        transform,
        evidence,
        (
            f"{transform} output was estimated at "
            f"{estimated_size} bytes and exceeded "
            "the configured maximum decoded size of "
            f"{maximum_output_bytes} bytes."
        ),
    )


def _decoded_content_quality(
    data: bytes,
) -> Tuple[bool, str]:
    """Evaluate whether decoded bytes are analytically plausible.

    Text is considered plausible when it is substantially
    printable and contains at least one alphanumeric character.
    Supported compressed-data signatures are also accepted so
    recursive decompression can continue.
    """

    signatures = (
        (b"\x1f\x8b", "gzip"),
        (b"BZh", "Bzip2"),
        (b"\xfd7zXZ\x00", "XZ"),
    )

    for signature, name in signatures:
        if data.startswith(signature):
            return (
                True,
                f"Decoded bytes contained a recognized "
                f"{name} signature",
            )

    if len(data) >= 2:
        compression_method = data[0] & 0x0F
        header_value = (
            data[0] << 8
        ) + data[1]

        if (
            compression_method == 8
            and header_value % 31 == 0
        ):
            return (
                True,
                "Decoded bytes contained a valid-looking "
                "zlib header",
            )

    decoded_text, encoding, _ = bytes_to_text(data)
    ratio = printable_ratio(decoded_text)

    contains_signal = any(
        character.isalnum()
        for character in decoded_text
        if character != "\ufffd"
    )

    if ratio >= 0.85 and contains_signal:
        return (
            True,
            "Decoded content was interpreted as "
            f"{encoding} with a printable-character "
            f"ratio of {ratio:.3f}",
        )

    return (
        False,
        "Decoded content did not contain a recognized "
        "compressed-data signature or sufficiently "
        "plausible text",
    )


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 digest of a byte sequence."""

    return hashlib.sha256(data).hexdigest()


def printable_ratio(text: str) -> float:
    """Calculate the proportion of inspectable characters.

    Unicode replacement characters are not counted as printable
    because they represent bytes that could not be decoded.
    """

    if not text:
        return 1.0

    printable_characters = sum(
        1
        for character in text
        if (
            character != "\ufffd"
            and (
                character.isprintable()
                or character in "\r\n\t"
            )
        )
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
    maximum_output_bytes: int = 1_048_576,
) -> List[TransformCandidate]:
    """Decode a plausible complete Base64 text stage."""

    candidate_text = _remove_whitespace(
        text.strip()
    )

    if len(candidate_text) < 8:
        return []

    if not _BASE64_PATTERN.fullmatch(
        candidate_text
    ):
        return []

    hexadecimal_value = candidate_text

    if hexadecimal_value.lower().startswith("0x"):
        hexadecimal_value = hexadecimal_value[2:]

    if (
        _HEX_PATTERN.fullmatch(candidate_text)
        and len(hexadecimal_value) >= 8
        and len(hexadecimal_value) % 2 == 0
    ):
        # Prefer the explicit hexadecimal interpretation.
        # This avoids generating duplicate Base64 branches from
        # values such as 41424344 or deadbeef.
        return []

    padded = _add_base64_padding(
        candidate_text
    )

    evidence = (
        "The complete stage matched a Base64 alphabet, "
        "decoded using strict validation, and produced "
        "analytically plausible content."
    )

    estimated_size = _base64_output_size(
        candidate_text
    )

    if estimated_size > maximum_output_bytes:
        return [
            _output_limit_candidate(
                "base64",
                evidence,
                estimated_size,
                maximum_output_bytes,
            )
        ]

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

        explicit_url_safe = (
            transform_name == "base64-url"
            and any(
                character in candidate_text
                for character in "-_"
            )
        )

        if explicit_url_safe:
            plausible = True
            quality_basis = (
                "The source used explicit URL-safe "
                "Base64 characters and decoded using "
                "strict validation"
            )
        else:
            plausible, quality_basis = (
                _decoded_content_quality(decoded)
            )

        if not plausible:
            continue

        candidates.append(
            TransformCandidate(
                transform=transform_name,
                decoded=decoded,
                confidence=confidence,
                evidence=(
                    f"{evidence} {quality_basis}."
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
    maximum_output_bytes: int = 1_048_576,
) -> List[TransformCandidate]:
    """Decode PowerShell EncodedCommand arguments as UTF-16LE."""

    candidates: List[TransformCandidate] = []

    for match in (
        _POWERSHELL_ENCODED_COMMAND_PATTERN.finditer(
            text
        )
    ):
        payload = match.group("payload")
        encoded_payload = _add_base64_padding(
            payload
        )

        estimated_size = _base64_output_size(
            payload
        )

        evidence = (
            "A PowerShell EncodedCommand "
            "argument was observed and its "
            "payload decoded successfully as "
            "UTF-16LE."
        )

        if estimated_size > maximum_output_bytes:
            candidates.append(
                _output_limit_candidate(
                    "powershell-encoded-command",
                    evidence,
                    estimated_size,
                    maximum_output_bytes,
                )
            )
            continue

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
                evidence=evidence,
            )
        )

    return candidates


def decode_hex_text(
    text: str,
    maximum_output_bytes: int = 1_048_576,
) -> List[TransformCandidate]:
    """Decode a plausible complete hexadecimal stage."""

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

    evidence = (
        "The complete stage contained an even-length "
        "hexadecimal value, decoded successfully, and "
        "produced analytically plausible content."
    )

    estimated_size = len(candidate_text) // 2

    if estimated_size > maximum_output_bytes:
        return [
            _output_limit_candidate(
                "hex",
                evidence,
                estimated_size,
                maximum_output_bytes,
            )
        ]

    try:
        decoded = bytes.fromhex(candidate_text)
    except ValueError:
        return []

    if not decoded:
        return []

    plausible, quality_basis = (
        _decoded_content_quality(decoded)
    )

    if not plausible:
        return []

    return [
        TransformCandidate(
            transform="hex",
            decoded=decoded,
            confidence=90,
            evidence=(
                f"{evidence} {quality_basis}."
            ),
        )
    ]


def decode_url_percent(
    text: str,
    maximum_output_bytes: int = 1_048_576,
) -> List[TransformCandidate]:
    """Decode percent-encoded bytes without network activity."""

    if not _PERCENT_PATTERN.search(text):
        return []

    evidence = (
        "The stage contained percent-encoded "
        "byte sequences that produced different "
        "decoded content."
    )

    estimated_size = _percent_decoded_size(text)

    if estimated_size > maximum_output_bytes:
        return [
            _output_limit_candidate(
                "url-percent",
                evidence,
                estimated_size,
                maximum_output_bytes,
            )
        ]

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
            evidence=evidence,
        )
    ]


def decode_html_entities(
    text: str,
    maximum_output_bytes: int = 1_048_576,
) -> List[TransformCandidate]:
    """Decode HTML character entities."""

    evidence = (
        "HTML character entities were present "
        "and produced different decoded content."
    )

    maximum_possible_size = _utf8_size(text)

    if maximum_possible_size > maximum_output_bytes:
        return [
            _output_limit_candidate(
                "html-entity",
                evidence,
                maximum_possible_size,
                maximum_output_bytes,
            )
        ]

    decoded = unescape(text)

    if decoded == text:
        return []

    return [
        TransformCandidate(
            transform="html-entity",
            decoded=decoded.encode("utf-8"),
            confidence=80,
            evidence=evidence,
        )
    ]


def reconstruct_string_concatenation(
    text: str,
    maximum_output_bytes: int = 1_048_576,
) -> List[TransformCandidate]:
    """Safely join simple quoted strings connected by plus signs.

    This function performs literal reconstruction only. It does not
    evaluate variables, functions, expressions, or executable code.
    """

    evidence = (
        "Two or more quoted string literals "
        "joined with plus signs were safely "
        "reconstructed without evaluating code."
    )

    maximum_possible_size = _utf8_size(text)

    if maximum_possible_size > maximum_output_bytes:
        return [
            _output_limit_candidate(
                "string-concatenation",
                evidence,
                maximum_possible_size,
                maximum_output_bytes,
            )
        ]

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
            evidence=evidence,
        )
    ]


def _trailing_data_warning(
    format_name: str,
    trailing_bytes: int,
) -> str:
    """Describe bytes remaining after one compressed member."""

    unit = (
        "byte"
        if trailing_bytes == 1
        else "bytes"
    )

    return (
        f"{trailing_bytes} trailing {unit} remained "
        f"after the first {format_name} compressed "
        "member. Additional members or appended data "
        "were not processed."
    )


def _decompress_zlib_limited(
    data: bytes,
    window_bits: int,
    maximum_output_bytes: int,
) -> Tuple[bytes, bytes]:
    """Decompress gzip or zlib with an output limit.

    Return the decoded first member and any bytes that
    remained after that member.
    """

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
        maximum_output_bytes + 1
        - len(output)
    )

    if remaining > 0:
        output += decompressor.flush(
            remaining
        )

    if len(output) > maximum_output_bytes:
        raise OutputLimitError

    return (
        output,
        decompressor.unused_data,
    )


def decode_gzip_bytes(
    data: bytes,
    maximum_output_bytes: int,
) -> List[TransformCandidate]:
    """Decode the first gzip member identified by magic bytes."""

    if not data.startswith(b"\x1f\x8b"):
        return []

    evidence = (
        "The stage began with the gzip magic bytes "
        "1F 8B."
    )

    try:
        decoded, trailing_data = (
            _decompress_zlib_limited(
                data,
                16 + zlib.MAX_WBITS,
                maximum_output_bytes,
            )
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

    warnings: List[str] = []

    if trailing_data:
        warnings.append(
            _trailing_data_warning(
                "gzip",
                len(trailing_data),
            )
        )

    return [
        TransformCandidate(
            transform="gzip",
            decoded=decoded,
            confidence=100,
            evidence=evidence,
            warnings=warnings,
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
    """Decode the first zlib stream after header validation."""

    if not _looks_like_zlib(data):
        return []

    evidence = (
        "The stage contained a valid-looking zlib "
        "header using the DEFLATE compression method."
    )

    try:
        decoded, trailing_data = (
            _decompress_zlib_limited(
                data,
                zlib.MAX_WBITS,
                maximum_output_bytes,
            )
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

    warnings: List[str] = []

    if trailing_data:
        warnings.append(
            _trailing_data_warning(
                "zlib",
                len(trailing_data),
            )
        )

    return [
        TransformCandidate(
            transform="zlib",
            decoded=decoded,
            confidence=95,
            evidence=evidence,
            warnings=warnings,
        )
    ]


def decode_bzip2_bytes(
    data: bytes,
    maximum_output_bytes: int,
) -> List[TransformCandidate]:
    """Decode the first Bzip2 member identified by BZh."""

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

    warnings: List[str] = []

    if decompressor.unused_data:
        warnings.append(
            _trailing_data_warning(
                "Bzip2",
                len(decompressor.unused_data),
            )
        )

    return [
        TransformCandidate(
            transform="bzip2",
            decoded=decoded,
            confidence=100,
            evidence=evidence,
            warnings=warnings,
        )
    ]


def decode_xz_bytes(
    data: bytes,
    maximum_output_bytes: int,
    maximum_memory_bytes: int = 67_108_864,
) -> List[TransformCandidate]:
    """Decode the first XZ member under size and memory limits."""

    if not data.startswith(b"\xfd7zXZ\x00"):
        return []

    evidence = (
        "The stage began with the XZ container "
        "signature used for LZMA2-compressed data."
    )

    decompressor = lzma.LZMADecompressor(
        format=lzma.FORMAT_XZ,
        memlimit=maximum_memory_bytes,
    )

    try:
        decoded = decompressor.decompress(
            data,
            max_length=maximum_output_bytes + 1,
        )
    except lzma.LZMAError as error:
        message = str(error)

        if "memory" in message.lower():
            warning = (
                "XZ decompression exceeded the "
                "configured memory limit of "
                f"{maximum_memory_bytes} bytes."
            )
        else:
            warning = (
                "Malformed XZ stream: "
                f"{error}"
            )

        return [
            _warning_candidate(
                "xz",
                evidence,
                warning,
            )
        ]

    if len(decoded) > maximum_output_bytes:
        return [
            _warning_candidate(
                "xz",
                evidence,
                "XZ output exceeded the configured "
                "maximum decoded size.",
            )
        ]

    if not decompressor.eof:
        if not decompressor.needs_input:
            return [
                _warning_candidate(
                    "xz",
                    evidence,
                    "XZ output exceeded the configured "
                    "maximum decoded size.",
                )
            ]

        return [
            _warning_candidate(
                "xz",
                evidence,
                "The XZ stream was incomplete.",
            )
        ]

    warnings: List[str] = []

    if decompressor.unused_data:
        warnings.append(
            _trailing_data_warning(
                "XZ",
                len(decompressor.unused_data),
            )
        )

    return [
        TransformCandidate(
            transform="xz",
            decoded=decoded,
            confidence=100,
            evidence=evidence,
            warnings=warnings,
        )
    ]
