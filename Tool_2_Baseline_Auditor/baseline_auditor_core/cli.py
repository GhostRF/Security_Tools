"""Command-line interface for the baseline auditor."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .checks import run_audit
from .profiles import (
    ProfileError,
    available_profiles,
    load_profile,
    resolve_profile_path,
)
from .reporters import write_all
from .scoring import summarize, threshold_exceeded


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"Security Baseline Compliance Auditor v{__version__}"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Directory containing exported configuration artifacts",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="baseline_auditor_output",
        help="Output directory",
    )
    parser.add_argument(
        "--profile",
        default="default",
        help=(
            "Bundled profile name or path to a JSON profile "
            "(default: default)"
        ),
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List bundled profiles and exit",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help=(
            "Return exit code 1 when failed findings meet or exceed "
            "--fail-level"
        ),
    )
    parser.add_argument(
        "--fail-level",
        choices=["low", "medium", "high", "critical"],
        default="high",
        help=(
            "Minimum failed severity that triggers exit code 1 when "
            "--fail-on-findings is used (default: high)"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _print_profiles() -> None:
    print("Bundled profiles:")
    for path in available_profiles():
        try:
            profile = load_profile(path)
            print(
                f"  {profile.profile_id}: {profile.name} "
                f"(v{profile.version})"
            )
        except ProfileError as exc:
            print(f"  {path.name}: invalid profile ({exc})")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_profiles:
        _print_profiles()
        return 0

    if not args.target:
        parser.error("the following arguments are required: target")

    target_dir = Path(args.target).expanduser()
    if not target_dir.exists() or not target_dir.is_dir():
        print(
            "[ERROR] Target directory does not exist or is not a directory: "
            f"{target_dir}"
        )
        return 2

    try:
        profile_path = resolve_profile_path(args.profile)
        profile = load_profile(profile_path)
    except ProfileError as exc:
        print(f"[ERROR] {exc}")
        return 2

    out_dir = Path(args.output).expanduser()

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        findings = run_audit(target_dir, profile)
        summary = summarize(findings, profile)
        write_all(findings, profile, out_dir)
    except OSError as exc:
        print(f"[ERROR] Could not complete audit: {exc}")
        return 3

    print(f"Security Baseline Compliance Auditor v{__version__}")
    print(
        f"Profile: {profile.name} "
        f"({profile.profile_id} v{profile.version})"
    )
    print(f"Baseline checks run: {summary['total_checks']}")
    print(f"Passed: {summary['passed']}")
    print(f"Failed: {summary['failed']}")
    print(f"Compliance score: {summary['compliance_score']}%")
    print(f"Critical findings: {summary['critical']}")
    print(f"High findings: {summary['high']}")
    print(f"Medium findings: {summary['medium']}")
    print(f"Low findings: {summary['low']}")
    print(f"Output written to: {out_dir.resolve()}")

    if args.fail_on_findings and threshold_exceeded(
        findings,
        args.fail_level,
    ):
        return 1

    return 0
