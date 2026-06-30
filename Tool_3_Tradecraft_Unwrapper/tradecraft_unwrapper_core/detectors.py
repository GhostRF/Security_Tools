"""Detection coordination for supported transformations."""

from __future__ import annotations

from typing import List, Optional, Set, Tuple

from .models import TransformCandidate
from .transforms import (
    decode_base64_text,
    decode_bzip2_bytes,
    decode_gzip_bytes,
    decode_hex_text,
    decode_html_entities,
    decode_xz_bytes,
    decode_powershell_encoded_command,
    decode_url_percent,
    decode_zlib_bytes,
    reconstruct_string_concatenation,
)


def detect_transforms(
    text: str,
    data: Optional[bytes] = None,
    *,
    allow_text: bool = True,
    maximum_output_bytes: int = 1_048_576,
    maximum_lzma_memory_bytes: int = 67_108_864,
) -> List[TransformCandidate]:
    """Identify safe decoding candidates for one stage."""

    candidates: List[TransformCandidate] = []

    if data is not None:
        candidates.extend(
            decode_gzip_bytes(
                data,
                maximum_output_bytes,
            )
        )

        candidates.extend(
            decode_zlib_bytes(
                data,
                maximum_output_bytes,
            )
        )

        candidates.extend(
            decode_bzip2_bytes(
                data,
                maximum_output_bytes,
            )
        )

        candidates.extend(
            decode_xz_bytes(
                data,
                maximum_output_bytes,
                maximum_lzma_memory_bytes,
            )
        )

    if allow_text:
        candidates.extend(
            decode_powershell_encoded_command(
                text,
                maximum_output_bytes,
            )
        )

        candidates.extend(
            decode_url_percent(
                text,
                maximum_output_bytes,
            )
        )

        candidates.extend(
            decode_html_entities(
                text,
                maximum_output_bytes,
            )
        )

        candidates.extend(
            reconstruct_string_concatenation(
                text,
                maximum_output_bytes,
            )
        )

        candidates.extend(
            decode_base64_text(
                text,
                maximum_output_bytes,
            )
        )

        candidates.extend(
            decode_hex_text(
                text,
                maximum_output_bytes,
            )
        )

    results: List[TransformCandidate] = []
    seen: Set[Tuple[str, bytes]] = set()

    for candidate in candidates:
        identity = (
            candidate.transform,
            candidate.decoded,
        )

        if identity in seen:
            continue

        seen.add(identity)
        results.append(candidate)

    return sorted(
        results,
        key=lambda candidate: candidate.confidence,
        reverse=True,
    )
