"""Command-line interface for Tradecraft Unwrapper."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .pipeline import AnalyzerConfig, analyze_bytes
from .reporters import write_reports


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

    if not 0.0 <= arguments.min_printable_ratio <= 1.0:
        parser.error(
            "--min-printable-ratio must be between 0 and 1"
        )

    if arguments.text is not None:
        source = "<literal-text>"
        data = arguments.text.encode("utf-8")
    else:
        input_path = Path(arguments.input).expanduser()

        if not input_path.exists() or not input_path.is_file():
            print(
                "[ERROR] Input file does not exist: "
                f"{input_path}"
            )
            return 2

        try:
            data = input_path.read_bytes()
        except OSError as error:
            print(
                "[ERROR] Could not read input file: "
                f"{error}"
            )
            return 3

        source = str(input_path)

    configuration = AnalyzerConfig(
        max_depth=arguments.max_depth,
        max_output_bytes=arguments.max_bytes,
        min_printable_ratio=arguments.min_printable_ratio,
    )

    result = analyze_bytes(
        data,
        source,
        configuration,
    )

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
        f"Stages observed: {len(result.stages)}"
    )
    print(
        "Decoded stages: "
        f"{max(0, len(result.stages) - 1)}"
    )
    print(
        "Indicators extracted: "
        f"{len(result.indicators)}"
    )
    print(
        "Output written to: "
        f"{output_directory.resolve()}"
    )

    return 0
