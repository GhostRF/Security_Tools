"""Recursive, non-executing transformation pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import platform
from typing import Dict, List, Optional, Tuple

from . import __version__
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


class AnalysisLimitError(ValueError):
    """Raised when an analysis resource limit is exceeded."""


@dataclass(frozen=True)
class AnalyzerConfig:
    """Safety and processing limits for recursive analysis."""

    max_depth: int = 5
    max_output_bytes: int = 1_048_576
    max_input_bytes: int = 10_485_760
    max_stages: int = 100
    max_total_output_bytes: int = 10_485_760
    max_xz_memory_bytes: int = 67_108_864
    min_printable_ratio: float = 0.60
    rules_path: Optional[Path] = None


def analyze_bytes(
    data: bytes,
    source: str,
    config: AnalyzerConfig,
) -> AnalysisResult:
    """Analyze bytes recursively without executing content."""

    if len(data) > config.max_input_bytes:
        raise AnalysisLimitError(
            f"Input contained {len(data)} bytes, which "
            "exceeded the configured maximum input size "
            f"of {config.max_input_bytes} bytes."
        )

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
    stage_bytes = {
        root_stage.stage_id: data,
    }

    processing_queue: List[
        Tuple[Stage, bytes]
    ] = [
        (root_stage, data)
    ]

    observed_hashes: Dict[str, int] = {
        root_hash: root_stage.stage_id
    }

    analysis_warnings: List[str] = []
    total_decoded_bytes = 0
    stage_limit_reached = False

    while processing_queue and not stage_limit_reached:
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
            maximum_lzma_memory_bytes=(
                config.max_xz_memory_bytes
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

            if len(stages) >= config.max_stages:
                analysis_warnings.append(
                    "Stopped recursive processing because "
                    "the configured maximum stage count of "
                    f"{config.max_stages} was reached."
                )
                stage_limit_reached = True
                processing_queue.clear()
                break

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

            projected_total = (
                total_decoded_bytes
                + decoded_size
            )

            if (
                projected_total
                > config.max_total_output_bytes
            ):
                analysis_warnings.append(
                    f"Skipped {candidate.transform} "
                    f"output from stage "
                    f"{parent.stage_id}: adding "
                    f"{decoded_size} bytes would exceed "
                    "the configured cumulative decoded "
                    "output limit of "
                    f"{config.max_total_output_bytes} bytes."
                )
                continue

            output_hash = sha256_hex(
                candidate.decoded
            )

            existing_stage_id = observed_hashes.get(
                output_hash
            )

            if existing_stage_id is not None:
                analysis_warnings.append(
                    f"Skipped duplicate "
                    f"{candidate.transform} output from "
                    f"stage {parent.stage_id}: SHA-256 "
                    f"{output_hash} is already represented "
                    f"by stage {existing_stage_id}."
                )
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
            total_decoded_bytes += decoded_size

            stage_bytes[
                child_stage.stage_id
            ] = candidate.decoded
            observed_hashes[
                output_hash
            ] = child_stage.stage_id

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

    provenance = {
        "tool_name": "Tradecraft Unwrapper",
        "tool_version": __version__,
        "generated_at_utc": (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        ),
        "python_version": platform.python_version(),
        "analysis_mode": "static-non-executing",
        "lineage_policy": (
            "unique-output-sha256-deduplication"
        ),
        "limits": {
            "max_depth": config.max_depth,
            "max_stage_output_bytes": (
                config.max_output_bytes
            ),
            "max_input_bytes": config.max_input_bytes,
            "max_stages": config.max_stages,
            "max_total_decoded_bytes": (
                config.max_total_output_bytes
            ),
            "max_xz_memory_bytes": (
                config.max_xz_memory_bytes
            ),
            "min_printable_ratio": (
                config.min_printable_ratio
            ),
        },
    }

    return AnalysisResult(
        source=source,
        root_sha256=root_hash,
        stages=stages,
        indicators=indicators,
        findings=findings,
        ruleset=ruleset_metadata,
        provenance=provenance,
        stage_bytes=stage_bytes,
        warnings=analysis_warnings,
    )
