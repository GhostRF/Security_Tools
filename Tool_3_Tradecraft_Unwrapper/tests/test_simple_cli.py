"""CLI tests for simple decoded-output mode."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
import unittest


TOOL_DIRECTORY = Path(__file__).resolve().parents[1]
SCRIPT = TOOL_DIRECTORY / "tradecraft_unwrapper.py"


class SimpleCliTests(unittest.TestCase):
    """Validate compact decoded-output behavior."""

    def test_simple_mode_prints_decoded_stage_text(self) -> None:
        encoded_text = (
            "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp"
            "LkRvd25sb2FkU3RyaW5nKCJodHRwOi8vZXZpbC94Iik="
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory) / "simple-output"

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--text",
                    encoded_text,
                    "--simple",
                    "-o",
                    str(output_directory),
                ],
                cwd=TOOL_DIRECTORY,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("Simple decoded output:", completed.stdout)
            self.assertIn("IEX", completed.stdout)
            self.assertIn("New-Object Net.WebClient", completed.stdout)
            self.assertTrue((output_directory / "analysis.json").exists())
            self.assertTrue((output_directory / "summary.txt").exists())


if __name__ == "__main__":
    unittest.main()
