"""Optional embedded encoded-fragment scanner.

This module is intentionally separate from the recursive stage pipeline.
It looks for likely Base64 or hexadecimal fragments embedded inside larger
text and reports candidates without automatically turning them into recursive
analysis stages.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import base64
import binascii
import re
import string
from typing import List


_BASE64_FRAGMENT_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{16,}={0,2})(?![A-Za-z0-9+/=_-])"
)

_HEX_FRAGMENT_RE = re.compile(
    r"(?<![A-Fa-f0-9])(?:0x)?([A-Fa-f0-9]{16,})(?![A-Fa-f0-9])"
)

_PRINTABLE = set(string.printable)


@dataclass(frozen=True)
class EmbeddedFragmentCandidate:
    """A likely encoded fragment found inside a larger text stage."""

    kind: str
    start: int
    end: int
    value: str
    decoded_size: int
    decoded_preview: str
    confidence: int
    evidence: str


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for character in text if character in _PRINTABLE) / len(text)


def _decode_bytes_to_preview(data: bytes, limit: int = 240) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def _is_plausible_decoded_text(data: bytes) -> bool:
    if not data:
        return False
    preview = _decode_bytes_to_preview(data, limit=1000)
    return _printable_ratio(preview) >= 0.75


def _add_base64_padding(value: str) -> str:
    remainder = len(value) % 4
    if remainder:
        value += "=" * (4 - remainder)
    return value


def _decode_base64_fragment(value: str, maximum_output_bytes: int) -> bytes | None:
    if len(value) < 16:
        return None

    if re.fullmatch(r"[A-Fa-f0-9]+", value) and len(value) % 2 == 0:
        return None

    padded = _add_base64_padding(value)

    try:
        decoded = base64.b64decode(
            padded.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError):
        return None

    if len(decoded) > maximum_output_bytes:
        return None

    if not _is_plausible_decoded_text(decoded):
        return None

    return decoded


def _decode_hex_fragment(value: str, maximum_output_bytes: int) -> bytes | None:
    candidate = value[2:] if value.lower().startswith("0x") else value

    if len(candidate) < 16 or len(candidate) % 2 != 0:
        return None

    try:
        decoded = bytes.fromhex(candidate)
    except ValueError:
        return None

    if len(decoded) > maximum_output_bytes:
        return None

    if not _is_plausible_decoded_text(decoded):
        return None

    return decoded


def scan_embedded_fragments(
    text: str,
    maximum_output_bytes: int = 1_048_576,
    maximum_candidates: int = 50,
) -> List[EmbeddedFragmentCandidate]:
    """Return likely embedded Base64 or hexadecimal fragments.

    The scan is conservative and report-only. It does not execute content,
    fetch network resources, or add new recursive stages automatically.
    """

    candidates: List[EmbeddedFragmentCandidate] = []
    occupied_spans: set[tuple[int, int]] = set()

    for match in _BASE64_FRAGMENT_RE.finditer(text):
        value = match.group(1)
        decoded = _decode_base64_fragment(value, maximum_output_bytes)
        if decoded is None:
            continue

        occupied_spans.add(match.span(1))
        candidates.append(
            EmbeddedFragmentCandidate(
                kind="embedded-base64",
                start=match.start(1),
                end=match.end(1),
                value=value,
                decoded_size=len(decoded),
                decoded_preview=_decode_bytes_to_preview(decoded),
                confidence=80,
                evidence=(
                    "Embedded fragment matched a Base64 alphabet, decoded "
                    "with strict validation, and produced printable text."
                ),
            )
        )

        if len(candidates) >= maximum_candidates:
            return candidates

    for match in _HEX_FRAGMENT_RE.finditer(text):
        span = match.span(1)
        if span in occupied_spans:
            continue

        value = match.group(1)
        decoded = _decode_hex_fragment(value, maximum_output_bytes)
        if decoded is None:
            continue

        candidates.append(
            EmbeddedFragmentCandidate(
                kind="embedded-hex",
                start=match.start(1),
                end=match.end(1),
                value=value,
                decoded_size=len(decoded),
                decoded_preview=_decode_bytes_to_preview(decoded),
                confidence=70,
                evidence=(
                    "Embedded fragment matched an even-length hexadecimal "
                    "pattern and produced printable text."
                ),
            )
        )

        if len(candidates) >= maximum_candidates:
            return candidates

    return candidates


def embedded_candidates_to_dicts(
    candidates: List[EmbeddedFragmentCandidate],
) -> list[dict[str, object]]:
    """Convert embedded-fragment candidates to JSON-serializable dictionaries."""

    return [asdict(candidate) for candidate in candidates]
