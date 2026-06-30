"""Command-line interface for Tradecraft Unwrapper."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
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
    print(
        "Output written to: "
        f"{output_directory.resolve()}"
    )

    return 0
