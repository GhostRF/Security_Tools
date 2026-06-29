"""Detection coordination for supported transformations."""

from __future__ import annotations

from typing import List, Set, Tuple

from .models import TransformCandidate
from .transforms import (
    decode_base64_text,
    decode_hex_text,
    decode_powershell_encoded_command,
    decode_url_percent,
)


def detect_transforms(text: str) -> List[TransformCandidate]:
    """Identify safe decoding candidates for one text stage.

    Detection only analyzes and decodes content. It never executes commands,
    invokes a shell, starts PowerShell, or performs network activity.
    """

    candidates: List[TransformCandidate] = []

    candidates.extend(decode_powershell_encoded_command(text))
    candidates.extend(decode_url_percent(text))
    candidates.extend(decode_base64_text(text))
    candidates.extend(decode_hex_text(text))

    results: List[TransformCandidate] = []
    seen: Set[Tuple[str, bytes]] = set()

    for candidate in candidates:
        identity = (candidate.transform, candidate.decoded)

        if identity in seen:
            continue

        seen.add(identity)
        results.append(candidate)

    return sorted(
        results,
        key=lambda candidate: candidate.confidence,
        reverse=True,
    )
