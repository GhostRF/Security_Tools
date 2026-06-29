"""Report generation for Tradecraft Unwrapper."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .models import AnalysisResult


def _stage_filename(stage_id: int, transform: str) -> str:
    safe_transform = "".join(
        character
        if character.isalnum() or character in "-_"
        else "_"
        for character in transform
    )

    return f"stage_{stage_id:02d}_{safe_transform}.txt"


def render_summary(result: AnalysisResult) -> str:
    """Render a human-readable analysis summary."""

    lines: List[str] = [
        "Tradecraft Unwrapper Analysis",
        f"Source: {result.source}",
        f"Root SHA-256: {result.root_sha256}",
        f"Stages observed: {len(result.stages)}",
        f"Decoded stages: {max(0, len(result.stages) - 1)}",
        f"Indicators extracted: {len(result.indicators)}",
        "",
        "Transformation lineage:",
    ]

    for stage in result.stages:
        parent = (
            "none"
            if stage.parent_id is None
            else str(stage.parent_id)
        )

        lines.append(
            f"  Stage {stage.stage_id}: "
            f"parent={parent}, "
            f"depth={stage.depth}, "
            f"transform={stage.transform}, "
            f"confidence={stage.confidence}, "
            f"bytes={stage.output_size}, "
            f"sha256={stage.output_sha256}"
        )

    if result.indicators:
        lines.extend(["", "Indicators:"])

        for indicator in result.indicators:
            lines.append(
                f"  [{indicator.kind}] "
                f"stage={indicator.stage_id} "
                f"{indicator.value}"
            )

    warnings = list(result.warnings)

    for stage in result.stages:
        warnings.extend(
            f"Stage {stage.stage_id}: {warning}"
            for warning in stage.warnings
        )

    if warnings:
        lines.extend(["", "Warnings:"])
        lines.extend(
            f"  - {warning}"
            for warning in warnings
        )

    return "\n".join(lines) + "\n"


def write_reports(
    result: AnalysisResult,
    output_directory: Path,
) -> None:
    """Write machine-readable and human-readable output files."""

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    stages_directory = output_directory / "stages"
    stages_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    analysis_path = output_directory / "analysis.json"
    analysis_path.write_text(
        json.dumps(
            result.to_dict(),
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    summary_path = output_directory / "summary.txt"
    summary_path.write_text(
        render_summary(result),
        encoding="utf-8",
    )

    for stage in result.stages:
        stage_path = stages_directory / _stage_filename(
            stage.stage_id,
            stage.transform,
        )

        stage_path.write_text(
            stage.text,
            encoding="utf-8",
        )
