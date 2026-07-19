"""Release-version regression test."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

TOOL_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIRECTORY))

from tradecraft_unwrapper_core import __version__


class VersionTests(unittest.TestCase):
    """Confirm that package and CLI release versions agree."""

    def test_release_version(self) -> None:
        self.assertEqual(
            __version__,
            "1.1.0",
        )

        completed = subprocess.run(
            [
                sys.executable,
                str(
                    TOOL_DIRECTORY
                    / "tradecraft_unwrapper.py"
                ),
                "--version",
            ],
            cwd=TOOL_DIRECTORY,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(
            completed.returncode,
            0,
            msg=completed.stderr,
        )

        self.assertIn(
            "1.1.0",
            completed.stdout,
        )


if __name__ == "__main__":
    unittest.main()
