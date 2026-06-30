"""Tests for raw stage preservation and HTML reporting."""

from __future__ import annotations

import base64
import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOL_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIRECTORY))

from tradecraft_unwrapper_core.pipeline import (
    AnalyzerConfig,
    analyze_bytes,
)
from tradecraft_unwrapper_core.reporters import (
    write_reports,
)


class ReportingTests(unittest.TestCase):
    """Validate forensic artifacts and safe HTML generation."""

    def test_raw_stage_artifacts_preserve_exact_bytes(
        self,
    ) -> None:
        final_content = (
            b'Write-Output "Raw artifact test"'
        )

        compressed = gzip.compress(
            final_content
        )

        encoded = base64.b64encode(
            compressed
        )

        result = analyze_bytes(
            encoded,
            "test-input",
            AnalyzerConfig(),
        )

        stage_ids = {
            stage.transform: stage.stage_id
            for stage in result.stages
        }

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)

            write_reports(
                result,
                output,
            )

            base64_stage = stage_ids["base64"]
            gzip_stage = stage_ids["gzip"]

            self.assertEqual(
                (
                    output
                    / "stages"
                    / (
                        f"stage_{base64_stage:02d}"
                        "_base64.bin"
                    )
                ).read_bytes(),
                compressed,
            )

            self.assertEqual(
                (
                    output
                    / "stages"
                    / (
                        f"stage_{gzip_stage:02d}"
                        "_gzip.bin"
                    )
                ).read_bytes(),
                final_content,
            )

    def test_html_report_escapes_analyzed_content(
        self,
    ) -> None:
        content = (
            b'powershell.exe -Command '
            b'"<script>alert(1)</script>"'
        )

        result = analyze_bytes(
            content,
            "test-input",
            AnalyzerConfig(),
        )

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)

            write_reports(
                result,
                output,
            )

            html = (
                output
                / "report.html"
            ).read_text(
                encoding="utf-8"
            )

            self.assertIn(
                "&lt;script&gt;"
                "alert(1)"
                "&lt;/script&gt;",
                html,
            )

            self.assertNotIn(
                "<script>alert(1)</script>",
                html,
            )

    def test_all_report_formats_are_generated(
        self,
    ) -> None:
        result = analyze_bytes(
            b"cmd.exe /c echo reporting",
            "test-input",
            AnalyzerConfig(),
        )

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)

            write_reports(
                result,
                output,
            )

            for filename in (
                "analysis.json",
                "summary.txt",
                "report.html",
            ):
                self.assertTrue(
                    (
                        output
                        / filename
                    ).is_file()
                )

            data = json.loads(
                (
                    output
                    / "analysis.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            self.assertNotIn(
                "stage_bytes",
                data,
            )


    def test_stage_confidence_is_clearly_labeled(
        self,
    ) -> None:
        result = analyze_bytes(
            b"cmd.exe /c echo confidence-label",
            "test-input",
            AnalyzerConfig(),
        )

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)

            write_reports(
                result,
                output,
            )

            html = (
                output
                / "report.html"
            ).read_text(
                encoding="utf-8"
            )

            summary = (
                output
                / "summary.txt"
            ).read_text(
                encoding="utf-8"
            )

            self.assertIn(
                "Transform confidence",
                html,
            )

            self.assertIn(
                "transform_confidence=",
                summary,
            )


if __name__ == "__main__":
    unittest.main()
