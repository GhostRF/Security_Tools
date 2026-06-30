"""Tests for recursive Tradecraft Unwrapper analysis."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote

TOOL_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIRECTORY))

from tradecraft_unwrapper_core.pipeline import (
    AnalyzerConfig,
    analyze_bytes,
)
from tradecraft_unwrapper_core.reporters import write_reports


class PipelineTests(unittest.TestCase):
    """Validate recursive analysis, limits, and reporting."""

    def setUp(self) -> None:
        self.configuration = AnalyzerConfig(
            max_depth=5,
            max_output_bytes=1_048_576,
            min_printable_ratio=0.60,
        )

    def test_base64_stage_is_created(self) -> None:
        original = b'Write-Output "Pipeline test"'
        encoded = base64.b64encode(original)

        result = analyze_bytes(
            encoded,
            "test-input",
            self.configuration,
        )

        self.assertGreaterEqual(
            len(result.stages),
            2,
        )

        self.assertTrue(
            any(
                stage.transform == "base64"
                and "Pipeline test" in stage.text
                for stage in result.stages
            )
        )

    def test_powershell_utf16le_is_rendered(self) -> None:
        command = 'Write-Output "PowerShell pipeline test"'

        encoded = base64.b64encode(
            command.encode("utf-16le")
        ).decode("ascii")

        input_text = (
            "powershell.exe -EncodedCommand "
            f"{encoded}"
        )

        result = analyze_bytes(
            input_text.encode("utf-8"),
            "test-input",
            self.configuration,
        )

        decoded_stage = next(
            stage
            for stage in result.stages
            if stage.transform
            == "powershell-encoded-command"
        )

        self.assertEqual(
            decoded_stage.text,
            command,
        )

        self.assertEqual(
            decoded_stage.text_encoding,
            "utf-16le",
        )

    def test_nested_base64_and_url_decoding(self) -> None:
        command = 'Write-Output "Nested pipeline test"'
        percent_encoded = quote(command, safe="")

        outer_layer = base64.b64encode(
            percent_encoded.encode("utf-8")
        )

        result = analyze_bytes(
            outer_layer,
            "test-input",
            self.configuration,
        )

        transforms = [
            stage.transform
            for stage in result.stages
        ]

        self.assertIn(
            "base64",
            transforms,
        )

        self.assertIn(
            "url-percent",
            transforms,
        )

        self.assertTrue(
            any(
                command == stage.text
                for stage in result.stages
            )
        )

    def test_maximum_depth_is_enforced(self) -> None:
        encoded = b"safe"

        for _ in range(4):
            encoded = base64.b64encode(encoded)

        result = analyze_bytes(
            encoded,
            "test-input",
            AnalyzerConfig(max_depth=1),
        )

        self.assertTrue(
            all(
                stage.depth <= 1
                for stage in result.stages
            )
        )

        self.assertTrue(
            any(
                "maximum depth" in warning
                for warning in result.warnings
            )
        )

    def test_reports_are_generated(self) -> None:
        encoded = base64.b64encode(
            b'Write-Output "Report test"'
        )

        result = analyze_bytes(
            encoded,
            "test-input",
            self.configuration,
        )

        with tempfile.TemporaryDirectory() as temporary:
            output_directory = Path(temporary)

            write_reports(
                result,
                output_directory,
            )

            self.assertTrue(
                (
                    output_directory
                    / "analysis.json"
                ).is_file()
            )

            self.assertTrue(
                (
                    output_directory
                    / "summary.txt"
                ).is_file()
            )

            self.assertTrue(
                (
                    output_directory
                    / "stages"
                ).is_dir()
            )

            report = json.loads(
                (
                    output_directory
                    / "analysis.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            self.assertGreaterEqual(
                len(report["stages"]),
                2,
            )

    def test_cli_generates_output(self) -> None:
        encoded = base64.b64encode(
            b'Write-Output "CLI test"'
        ).decode("ascii")

        with tempfile.TemporaryDirectory() as temporary:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(
                        TOOL_DIRECTORY
                        / "tradecraft_unwrapper.py"
                    ),
                    "--text",
                    encoded,
                    "-o",
                    temporary,
                ],
                cwd=TOOL_DIRECTORY,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(
                completed.returncode,
                0,
            )

            self.assertIn(
                "Derived stages:",
                completed.stdout,
            )

            self.assertTrue(
                (
                    Path(temporary)
                    / "analysis.json"
                ).is_file()
            )


if __name__ == "__main__":
    unittest.main()
