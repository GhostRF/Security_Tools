"""Tests for global analysis resource limits."""

from __future__ import annotations

import base64
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIRECTORY))

from tradecraft_unwrapper_core.pipeline import (
    AnalysisLimitError,
    AnalyzerConfig,
    analyze_bytes,
)


class ResourceLimitTests(unittest.TestCase):
    """Verify input, stage-count, and cumulative limits."""

    def test_direct_analysis_rejects_oversized_input(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            AnalysisLimitError,
            "maximum input size",
        ):
            analyze_bytes(
                b"A" * 11,
                "oversized-input",
                AnalyzerConfig(
                    max_input_bytes=10,
                ),
            )

    def test_cli_rejects_file_before_analysis(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            input_path = temporary_path / "large.txt"
            output_path = temporary_path / "output"

            input_path.write_bytes(
                b"A" * 20
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(
                        TOOL_DIRECTORY
                        / "tradecraft_unwrapper.py"
                    ),
                    str(input_path),
                    "--max-input-bytes",
                    "10",
                    "-o",
                    str(output_path),
                ],
                cwd=TOOL_DIRECTORY,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(
                completed.returncode,
                5,
                msg=completed.stderr,
            )

            self.assertIn(
                "maximum input size",
                completed.stdout,
            )

            self.assertFalse(
                output_path.exists()
            )

    def test_maximum_stage_count_is_enforced(
        self,
    ) -> None:
        final_content = (
            b'cmd.exe /c echo "stage limit"'
        )

        first_layer = base64.b64encode(
            final_content
        )

        second_layer = base64.b64encode(
            first_layer
        )

        result = analyze_bytes(
            second_layer,
            "stage-limit-input",
            AnalyzerConfig(
                max_stages=2,
            ),
        )

        self.assertEqual(
            len(result.stages),
            2,
        )

        self.assertTrue(
            any(
                "maximum stage count of 2"
                in warning
                for warning in result.warnings
            )
        )

    def test_cumulative_output_limit_is_enforced(
        self,
    ) -> None:
        final_content = (
            b'cmd.exe /c echo "total limit"'
        )

        first_layer = base64.b64encode(
            final_content
        )

        second_layer = base64.b64encode(
            first_layer
        )

        result = analyze_bytes(
            second_layer,
            "total-limit-input",
            AnalyzerConfig(
                max_total_output_bytes=(
                    len(first_layer)
                ),
            ),
        )

        self.assertEqual(
            len(result.stages),
            2,
        )

        self.assertTrue(
            any(
                "cumulative decoded output limit"
                in warning
                for warning in result.warnings
            )
        )


if __name__ == "__main__":
    unittest.main()
