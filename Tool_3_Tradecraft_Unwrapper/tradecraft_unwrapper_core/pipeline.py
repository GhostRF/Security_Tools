"""Recursive, non-executing transformation pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Tuple

from .detectors import detect_transforms
from .indicators import extract_indicators
from .models import AnalysisResult, Stage
from .tradecraft import (
    evaluate_tradecraft,
    load_ruleset,
)
from .transforms import (
    bytes_to_text,
    printable_ratio,
    sha256_hex,
)


@dataclass(frozen=True)
class AnalyzerConfig:
    """Safety and processing limits for recursive analysis."""

    max_depth: int = 5
    max_output_bytes: int = 1_048_576
    min_printable_ratio: float = 0.60
    rules_path: Optional[Path] = None


def analyze_bytes(
    data: bytes,
    source: str,
    config: AnalyzerConfig,
) -> AnalysisResult:
    """Analyze bytes recursively without executing content."""

    root_text, root_encoding, root_warnings = (
        bytes_to_text(data)
    )

    root_hash = sha256_hex(data)

    root_stage = Stage(
        stage_id=0,
        parent_id=None,
        depth=0,
        transform="input",
        confidence=100,
        evidence="Original analyst-supplied input.",
        input_sha256=root_hash,
        output_sha256=root_hash,
        input_size=len(data),
        output_size=len(data),
        text=root_text,
        text_encoding=root_encoding,
        printable_ratio=printable_ratio(root_text),
        warnings=root_warnings,
    )

    stages: List[Stage] = [root_stage]

    processing_queue: List[
        Tuple[Stage, bytes]
    ] = [
        (root_stage, data)
    ]

    observed_hashes: Set[str] = {
        root_hash
    }

    analysis_warnings: List[str] = []

    while processing_queue:
        parent, parent_data = (
            processing_queue.pop(0)
        )

        if parent.depth >= config.max_depth:
            analysis_warnings.append(
                f"Stage {parent.stage_id} reached "
                f"maximum depth {config.max_depth}. "
                "No additional decoding was attempted."
            )
            continue

        allow_text_decoders = (
            parent.printable_ratio
            >= config.min_printable_ratio
        )

        candidates = detect_transforms(
            parent.text,
            parent_data,
            allow_text=allow_text_decoders,
            maximum_output_bytes=(
                config.max_output_bytes
            ),
        )

        for candidate in candidates:
            if candidate.confidence <= 0:
                analysis_warnings.extend(
                    f"Stage {parent.stage_id}: "
                    f"{warning}"
                    for warning in candidate.warnings
                )
                continue

            decoded_size = len(
                candidate.decoded
            )

            if (
                decoded_size
                > config.max_output_bytes
            ):
                analysis_warnings.append(
                    f"Skipped {candidate.transform} "
                    f"output from stage "
                    f"{parent.stage_id}: "
                    f"{decoded_size} bytes exceeded "
                    "the configured limit of "
                    f"{config.max_output_bytes} bytes."
                )
                continue

            output_hash = sha256_hex(
                candidate.decoded
            )

            if output_hash in observed_hashes:
                continue

            (
                decoded_text,
                encoding,
                decoding_warnings,
            ) = bytes_to_text(
                candidate.decoded
            )

            ratio = printable_ratio(
                decoded_text
            )

            child_stage = Stage(
                stage_id=len(stages),
                parent_id=parent.stage_id,
                depth=parent.depth + 1,
                transform=candidate.transform,
                confidence=candidate.confidence,
                evidence=candidate.evidence,
                input_sha256=(
                    parent.output_sha256
                ),
                output_sha256=output_hash,
                input_size=parent.output_size,
                output_size=decoded_size,
                text=decoded_text,
                text_encoding=encoding,
                printable_ratio=ratio,
                warnings=(
                    list(candidate.warnings)
                    + list(decoding_warnings)
                ),
            )

            if (
                ratio
                < config.min_printable_ratio
            ):
                child_stage.warnings.append(
                    "The printable-character ratio "
                    "was below the text-decoding "
                    "threshold. Text-oriented decoders "
                    "will be skipped, but binary "
                    "signature decoders remain enabled."
                )

            stages.append(child_stage)
            observed_hashes.add(output_hash)

            processing_queue.append(
                (
                    child_stage,
                    candidate.decoded,
                )
            )

    indicators = extract_indicators(stages)
    ruleset = load_ruleset(config.rules_path)

    findings = evaluate_tradecraft(
        stages,
        indicators,
        ruleset,
    )

    ruleset_metadata = {
        "ruleset_id": ruleset["ruleset_id"],
        "name": ruleset["name"],
        "version": ruleset["version"],
        "source_path": ruleset["_source_path"],
    }

    return AnalysisResult(
        source=source,
        root_sha256=root_hash,
        stages=stages,
        indicators=indicators,
        findings=findings,
        ruleset=ruleset_metadata,
        warnings=analysis_warnings,
    )
