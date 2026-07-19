"""Command-line interface for Tradecraft Unwrapper."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .embedded import (
    embedded_candidates_to_dicts,
    scan_embedded_fragments,
)
from .pipeline import (
    AnalysisLimitError,
    AnalyzerConfig,
    analyze_bytes,
)
from .reporters import write_reports
from .tradecraft import RulesetError


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""

    parser = argparse.ArgumentParser(
        description=(
            f"Tradecraft Unwrapper v{__version__}: safely reconstruct "
            "encoded script and command stages without executing them."
        )
    )

    parser.add_argument(
        "input",
        nargs="?",
        help="Path to a text or binary input file",
    )

    parser.add_argument(
        "--text",
        help="Analyze a literal command or text string",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="output",
        help="Output directory (default: output)",
    )

    parser.add_argument(
        "--rules",
        help=(
            "Path to an external JSON tradecraft rule set. "
            "The bundled default rules are used when omitted."
        ),
    )

    parser.add_argument(
        "--simple",
        action="store_true",
        help=(
            "Print decoded derived stage text directly to the terminal "
            "while still writing the full analysis reports."
        ),
    )

    parser.add_argument(
        "--scan-embedded",
        action="store_true",
        help=(
            "Also scan the original input for likely embedded Base64 or "
            "hexadecimal fragments and write embedded_fragments reports."
        ),
    )

    parser.add_argument(
        "--max-depth",
        type=int,
        default=5,
        help="Maximum recursive decoding depth (default: 5)",
    )

    parser.add_argument(
        "--max-bytes",
        type=int,
        default=1_048_576,
        help=(
            "Maximum bytes accepted from one decoded stage "
            "(default: 1048576)"
        ),
    )

    parser.add_argument(
        "--max-input-bytes",
        type=int,
        default=10_485_760,
        help=(
            "Maximum input-file or literal-text size "
            "in bytes (default: 10485760)"
        ),
    )

    parser.add_argument(
        "--max-stages",
        type=int,
        default=100,
        help=(
            "Maximum number of stages, including the "
            "original input (default: 100)"
        ),
    )

    parser.add_argument(
        "--max-total-bytes",
        type=int,
        default=10_485_760,
        help=(
            "Maximum cumulative bytes accepted from all "
            "decoded stages (default: 10485760)"
        ),
    )

    parser.add_argument(
        "--max-xz-memory-bytes",
        type=int,
        default=67_108_864,
        help=(
            "Maximum memory allowed for XZ "
            "decompression (default: 67108864)"
        ),
    )

    parser.add_argument(
        "--min-printable-ratio",
        type=float,
        default=0.60,
        help=(
            "Minimum printable-character ratio required for recursive "
            "processing (default: 0.60)"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def _print_simple_stage_output(output_directory: Path) -> None:
    """Print derived stage text artifacts in a compact CLI-friendly format."""

    stages_directory = output_directory / "stages"
    stage_paths = sorted(stages_directory.glob("stage_*.txt"))

    derived_stage_paths = [
        stage_path
        for stage_path in stage_paths
        if not stage_path.name.startswith("stage_00_")
    ]

    print()
    print("Simple decoded output:")
    print("======================")

    if not derived_stage_paths:
        print("No decoded derived stage text was produced.")
        return

    for index, stage_path in enumerate(derived_stage_paths, start=1):
        stage_text = stage_path.read_text(
            encoding="utf-8",
            errors="replace",
        ).strip()

        if not stage_text:
            continue

        if len(derived_stage_paths) > 1:
            print()
            print(f"[Decoded stage {index}: {stage_path.name}]")

        print(stage_text)


def _write_embedded_fragment_reports(
    input_data: bytes,
    output_directory: Path,
    maximum_output_bytes: int,
) -> int:
    """Write optional embedded-fragment reports for the original input."""

    decoded_text = input_data.decode("utf-8", errors="replace")
    candidates = scan_embedded_fragments(
        decoded_text,
        maximum_output_bytes=maximum_output_bytes,
    )
    candidate_dicts = embedded_candidates_to_dicts(candidates)

    json_payload = {
        "count": len(candidate_dicts),
        "candidates": candidate_dicts,
    }

    json_path = output_directory / "embedded_fragments.json"
    text_path = output_directory / "embedded_fragments.txt"

    json_path.write_text(
        json.dumps(json_payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    lines = [
        "Embedded Fragment Candidates",
        "============================",
        "",
        f"Count: {len(candidate_dicts)}",
        "",
    ]

    if not candidates:
        lines.append("No likely embedded Base64 or hexadecimal fragments found.")
    else:
        for index, candidate in enumerate(candidates, start=1):
            lines.extend(
                [
                    f"Candidate {index}",
                    f"  Type: {candidate.kind}",
                    f"  Offset: {candidate.start}-{candidate.end}",
                    f"  Confidence: {candidate.confidence}",
                    f"  Decoded size: {candidate.decoded_size}",
                    f"  Evidence: {candidate.evidence}",
                    "  Decoded preview:",
                    f"    {candidate.decoded_preview}",
                    "",
                ]
            )

    text_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(candidate_dicts)


def main(
    argv: Optional[Sequence[str]] = None,
) -> int:
    """Run the Tradecraft Unwrapper command-line interface."""

    parser = build_parser()
    arguments = parser.parse_args(argv)

    if not arguments.input and arguments.text is None:
        parser.error(
            "provide an input file or use --text"
        )

    if arguments.input and arguments.text is not None:
        parser.error(
            "input file and --text cannot be used together"
        )

    if arguments.max_depth < 0:
        parser.error(
            "--max-depth must be zero or greater"
        )

    if arguments.max_bytes <= 0:
        parser.error(
            "--max-bytes must be greater than zero"
        )

    if arguments.max_input_bytes <= 0:
        parser.error(
            "--max-input-bytes must be greater than zero"
        )

    if arguments.max_stages <= 0:
        parser.error(
            "--max-stages must be greater than zero"
        )

    if arguments.max_total_bytes <= 0:
        parser.error(
            "--max-total-bytes must be greater than zero"
        )

    if arguments.max_xz_memory_bytes <= 0:
        parser.error(
            "--max-xz-memory-bytes must be greater than zero"
        )

    if not 0.0 <= arguments.min_printable_ratio <= 1.0:
        parser.error(
            "--min-printable-ratio must be between 0 and 1"
        )

    if arguments.text is not None:
        source = "<literal-text>"
        data = arguments.text.encode("utf-8")

        if len(data) > arguments.max_input_bytes:
            print(
                "[ERROR] Literal text contained "
                f"{len(data)} bytes, which exceeded "
                "the configured maximum input size of "
                f"{arguments.max_input_bytes} bytes."
            )
            return 5
    else:
        input_path = Path(arguments.input).expanduser()

        if not input_path.exists() or not input_path.is_file():
            print(
                "[ERROR] Input file does not exist: "
                f"{input_path}"
            )
            return 2

        try:
            input_size = input_path.stat().st_size
        except OSError as error:
            print(
                "[ERROR] Could not inspect input file: "
                f"{error}"
            )
            return 3

        if input_size > arguments.max_input_bytes:
            print(
                "[ERROR] Input file contained "
                f"{input_size} bytes, which exceeded "
                "the configured maximum input size of "
                f"{arguments.max_input_bytes} bytes."
            )
            return 5

        try:
            data = input_path.read_bytes()
        except OSError as error:
            print(
                "[ERROR] Could not read input file: "
                f"{error}"
            )
            return 3

        source = str(input_path)

    rules_path = (
        Path(arguments.rules).expanduser()
        if arguments.rules
        else None
    )

    configuration = AnalyzerConfig(
        max_depth=arguments.max_depth,
        max_output_bytes=arguments.max_bytes,
        max_input_bytes=arguments.max_input_bytes,
        max_stages=arguments.max_stages,
        max_total_output_bytes=(
            arguments.max_total_bytes
        ),
        max_xz_memory_bytes=(
            arguments.max_xz_memory_bytes
        ),
        min_printable_ratio=arguments.min_printable_ratio,
        rules_path=rules_path,
    )

    try:
        result = analyze_bytes(
            data,
            source,
            configuration,
        )
    except AnalysisLimitError as error:
        print(
            "[ERROR] Analysis resource limit: "
            f"{error}"
        )
        return 5
    except RulesetError as error:
        print(
            "[ERROR] Could not load tradecraft rules: "
            f"{error}"
        )
        return 4

    output_directory = Path(
        arguments.output
    ).expanduser()

    try:
        write_reports(
            result,
            output_directory,
        )
    except OSError as error:
        print(
            "[ERROR] Could not write reports: "
            f"{error}"
        )
        return 3

    embedded_fragment_count = None
    if arguments.scan_embedded:
        try:
            embedded_fragment_count = _write_embedded_fragment_reports(
                data,
                output_directory,
                arguments.max_bytes,
            )
        except OSError as error:
            print(
                "[ERROR] Could not write embedded-fragment reports: "
                f"{error}"
            )
            return 3

    print(
        f"Tradecraft Unwrapper v{__version__}"
    )
    print(f"Source: {source}")
    print(
        f"Unique stages recorded: {len(result.stages)}"
    )
    print(
        "Derived stages: "
        f"{max(0, len(result.stages) - 1)}"
    )
    print(
        "Indicators extracted: "
        f"{len(result.indicators)}"
    )
    print(
        "Tradecraft findings: "
        f"{len(result.findings)}"
    )
    if arguments.simple:
        _print_simple_stage_output(output_directory)

    if embedded_fragment_count is not None:
        print(f"Embedded fragments reported: {embedded_fragment_count}")

    print(
        "Output written to: "
        f"{output_directory.resolve()}"
    )

    return 0
