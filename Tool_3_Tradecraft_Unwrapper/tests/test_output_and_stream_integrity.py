"""Tests for output and compressed-stream integrity."""

from __future__ import annotations

import bz2
import gzip
import lzma
import sys
import tempfile
import unittest
import zlib
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
from tradecraft_unwrapper_core.transforms import (
    decode_bzip2_bytes,
    decode_gzip_bytes,
    decode_xz_bytes,
    decode_zlib_bytes,
)


class OutputAndStreamIntegrityTests(unittest.TestCase):
    """Verify output isolation and trailing-data warnings."""

    def assert_trailing_warning(
        self,
        candidates,
        expected: bytes,
    ) -> None:
        self.assertEqual(
            len(candidates),
            1,
        )

        candidate = candidates[0]

        self.assertGreater(
            candidate.confidence,
            0,
        )

        self.assertEqual(
            candidate.decoded,
            expected,
        )

        self.assertTrue(
            candidate.warnings
        )

        self.assertTrue(
            any(
                "trailing"
                in warning.lower()
                and "not processed"
                in warning.lower()
                for warning in candidate.warnings
            )
        )

    def test_nonempty_output_directory_is_rejected(
        self,
    ) -> None:
        result = analyze_bytes(
            b"ordinary benign training text",
            "output-integrity-input",
            AnalyzerConfig(),
        )

        with tempfile.TemporaryDirectory() as temporary:
            output = (
                Path(temporary)
                / "analysis-output"
            )

            write_reports(
                result,
                output,
            )

            with self.assertRaisesRegex(
                OSError,
                "not empty",
            ):
                write_reports(
                    result,
                    output,
                )

    def test_gzip_trailing_data_is_reported(
        self,
    ) -> None:
        payload = b"gzip training content"
        data = gzip.compress(payload) + b"TRAILING"

        self.assert_trailing_warning(
            decode_gzip_bytes(
                data,
                4096,
            ),
            payload,
        )

    def test_zlib_trailing_data_is_reported(
        self,
    ) -> None:
        payload = b"zlib training content"
        data = zlib.compress(payload) + b"TRAILING"

        self.assert_trailing_warning(
            decode_zlib_bytes(
                data,
                4096,
            ),
            payload,
        )

    def test_bzip2_trailing_data_is_reported(
        self,
    ) -> None:
        payload = b"bzip2 training content"
        data = bz2.compress(payload) + b"TRAILING"

        self.assert_trailing_warning(
            decode_bzip2_bytes(
                data,
                4096,
            ),
            payload,
        )

    def test_xz_trailing_data_is_reported(
        self,
    ) -> None:
        payload = b"xz training content"
        data = (
            lzma.compress(
                payload,
                format=lzma.FORMAT_XZ,
            )
            + b"TRAILING"
        )

        self.assert_trailing_warning(
            decode_xz_bytes(
                data,
                4096,
            ),
            payload,
        )


if __name__ == "__main__":
    unittest.main()
